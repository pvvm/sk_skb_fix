/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fix_test load generator: the q1 client without replies or latency timing.
 *
 * Open loop, one TCP connection, fixed-size messages sent back to back. The
 * offered load is set by a busy-wait spin count between sends (0 = flat out).
 * Messages are byte-for-byte what q1's client sends without --latency: same
 * header, sequence number, query mix (fixed seed) and padding.
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "fix_test_common.h"

static const char *const queries[] = {
	"SELECT * FROM users;",
	"SELECT id, name FROM users WHERE age > 18;",
	"INSERT INTO users (name, age) VALUES ('Alice', 25);",
	"INSERT INTO users (name, age) VALUES ('Bob', 30);",
	"UPDATE users SET age = 35 WHERE name = 'Alice';",
	"DELETE FROM users WHERE age < 18;",
	"SELECT COUNT(*) FROM users;",
	"SELECT * FROM orders WHERE user_id = 1;",
	"UPDATE orders SET status = 'shipped' WHERE id = 100;",
	"DELETE FROM orders WHERE status = 'cancelled';",
};
#define NQUERIES	(sizeof(queries) / sizeof(queries[0]))

static atomic_bool run_stop;

static void on_sigint(int sig) { (void)sig; atomic_store(&run_stop, true); }

static double now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Filler. Printable, never NUL, wrapped in a SQL comment when there is room. */
static void make_padding(char *dst, int len)
{
	if (len <= 0)
		return;
	memset(dst, ' ', len);
	if (len >= 5) {
		dst[0] = ' ';
		dst[1] = '/';
		dst[2] = '*';
		memset(dst + 3, 'a', len - 5);
		dst[len - 2] = '*';
		dst[len - 1] = '/';
	}
}

static void usage(const char *a0)
{
	fprintf(stderr,
"Usage: %s [options]\n"
"  --host IP        receiver                       (default 192.168.2.30)\n"
"  --port N         receiver port                  (default %d)\n"
"  --msg-size N     wire bytes per message; must match the receiver\n"
"  --spin N         busy-wait iterations between sends. THE LOAD KNOB, and\n"
"                   inverse: 0 is flat out, larger is slower\n"
"  --duration N     seconds to send for; 0 runs until the peer closes\n"
"  --cpu N|none     pin the send loop                (default 18)\n"
"  --connect-wait N seconds to keep retrying connect (default 30)\n"
"  --tag S          copied into the FTCLIENT block\n",
		a0, FT_PORT);
}

int main(int argc, char **argv)
{
	const char *host = "192.168.2.30", *tag = "";
	int port = FT_PORT, msg_size = 128, spin = 0, duration = 15, cpu = 18;
	int connect_wait = 30;
	int fd = -1;
	char *msg = NULL;
	unsigned long long sent_msgs = 0, sent_bytes = 0, short_sends = 0;
	/* Peak messages in any one-second bucket. The whole-run average
	 * understates the offered load once the receiver's window closes and
	 * this loop sits in send(); the peak second does not.
	 */
	unsigned long long bucket_msgs = 0, peak_msgs_per_s = 0;
	unsigned long long stuck_sends = 0;
	double bucket_start, t_start, t_end;

	{
		enum { O_HOST = 1000, O_PORT, O_MSG, O_SPIN, O_DUR, O_CPU,
		       O_WAIT, O_TAG, O_HELP };
		static const struct option lo[] = {
			{ "host",         required_argument, NULL, O_HOST },
			{ "port",         required_argument, NULL, O_PORT },
			{ "msg-size",     required_argument, NULL, O_MSG  },
			{ "spin",         required_argument, NULL, O_SPIN },
			{ "duration",     required_argument, NULL, O_DUR  },
			{ "cpu",          required_argument, NULL, O_CPU  },
			{ "connect-wait", required_argument, NULL, O_WAIT },
			{ "tag",          required_argument, NULL, O_TAG  },
			{ "help",         no_argument,       NULL, O_HELP },
			{ NULL, 0, NULL, 0 }
		};
		int c;

		while ((c = getopt_long(argc, argv, "h", lo, NULL)) != -1) {
			switch (c) {
			case O_HOST: host = optarg; break;
			case O_PORT: port = atoi(optarg); break;
			case O_MSG:  msg_size = atoi(optarg); break;
			case O_SPIN: spin = atoi(optarg); break;
			case O_DUR:  duration = atoi(optarg); break;
			case O_CPU:  cpu = strcmp(optarg, "none") ? atoi(optarg) : -1; break;
			case O_WAIT: connect_wait = atoi(optarg); break;
			case O_TAG:  tag = optarg; break;
			default:     usage(argv[0]); return c == O_HELP ? 0 : 2;
			}
		}
	}

	/* Header + sequence number + at least one byte of query + the NUL. */
	if (msg_size < FT_HEAD_SIZE + 4 + 2 || msg_size > FT_ACCESS_MAX) {
		fprintf(stderr, "--msg-size %d is outside [%d, %d]\n", msg_size,
			FT_HEAD_SIZE + 4 + 2, FT_ACCESS_MAX);
		return 2;
	}

	if (cpu >= 0) {
		cpu_set_t set;

		CPU_ZERO(&set);
		CPU_SET(cpu, &set);
		if (sched_setaffinity(0, sizeof(set), &set))
			fprintf(stderr, "send loop: sched_setaffinity(%d): %s\n",
				cpu, strerror(errno));
		else
			printf("send loop: pinned to CPU %d\n", cpu);
	}
	signal(SIGPIPE, SIG_IGN);
	{
		struct sigaction sa = { .sa_handler = on_sigint };

		sigemptyset(&sa.sa_mask);	/* no SA_RESTART: Ctrl-C must
						 * interrupt a blocked send() */
		sigaction(SIGINT, &sa, NULL);
	}

	{
		struct sockaddr_in sa = { .sin_family = AF_INET,
					  .sin_port = htons(port) };
		double deadline;

		inet_pton(AF_INET, host, &sa.sin_addr);
		deadline = now_s() + connect_wait;
		for (;;) {
			fd = socket(AF_INET, SOCK_STREAM, 0);
			if (fd < 0) { perror("socket"); return 1; }
			if (!connect(fd, (struct sockaddr *)&sa, sizeof(sa)))
				break;
			close(fd);
			fd = -1;
			if (now_s() > deadline) {
				fprintf(stderr, "connect to %s:%d timed out after %d s\n",
					host, port, connect_wait);
				return 1;
			}
			usleep(100000);
		}
	}
	/* Bound every blocking send(), or a full socket buffer keeps the loop
	 * from ever reaching the duration check.
	 */
	{
		struct timeval snd_to = { .tv_sec = 0, .tv_usec = 200000 };

		if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &snd_to, sizeof(snd_to)))
			perror("setsockopt(SO_SNDTIMEO)");
	}

	printf("connected to %s:%d, msg_size=%d spin=%d duration=%d\n",
	       host, port, msg_size, spin, duration);
	fflush(stdout);

	msg = malloc((size_t)msg_size);
	if (!msg) { fprintf(stderr, "out of memory\n"); return 1; }

	srand(1);				/* fixed seed: same message mix
						 * in every rep of every cell */
	t_start = now_s();
	bucket_start = t_start;

	while (!atomic_load_explicit(&run_stop, memory_order_relaxed)) {
		const int body = FT_HEAD_SIZE + 4;	/* header + sequence number */
		int q = rand() % NQUERIES;
		int qlen = (int)strlen(queries[q]);
		__u32 seq = (__u32)sent_msgs;
		int pad, length, i;
		ssize_t n;

		if (duration && now_s() - t_start >= duration)
			break;

		/* 'Q' | len | seq | query | pad | '\0' == msg_size */
		if (qlen > msg_size - body - 1)
			qlen = msg_size - body - 1;
		pad = msg_size - body - qlen - 1;

		length = msg_size - 1;	/* counts itself, not byte 0 */
		msg[0] = 'Q';
		memcpy(msg + 1, &length, 4);
		memcpy(msg + FT_SEQ_OFF, &seq, 4);
		memcpy(msg + body, queries[q], qlen);
		make_padding(msg + body + qlen, pad);
		msg[msg_size - 1] = '\0';

		/* Complete a partial send rather than moving on: a message sent
		 * short leaves the receiver's fixed-size framing out of step for
		 * the rest of the run.
		 */
		{
			size_t off = 0;
			bool broke = false;
			double t_msg = now_s();

			while (off < (size_t)msg_size) {
				n = send(fd, msg + off, msg_size - off, 0);
				if (n < 0) {
					if (errno == EINTR)
						continue;
					if (errno == EAGAIN || errno == EWOULDBLOCK) {
						/* SO_SNDTIMEO fired. Ending is only
						 * safe at a message boundary.
						 */
						if (off == 0 &&
						    (atomic_load(&run_stop) ||
						     (duration && now_s() - t_start >= duration))) {
							broke = true;
							break;
						}
						/* Mid-message and the peer has stopped
						 * draining for this long: give up.
						 */
						if (now_s() - t_msg > 10.0) {
							stuck_sends++;
							broke = true;
							break;
						}
						continue;
					}
					if (errno == EPIPE || errno == ECONNRESET)
						printf("peer closed the connection\n");
					else
						perror("send");
					broke = true;
					break;
				}
				if (off == 0 && n != msg_size)
					short_sends++;
				off += (size_t)n;
				sent_bytes += (unsigned long long)n;
			}
			if (broke)
				break;
		}
		sent_msgs++;
		bucket_msgs++;

		{
			double t = now_s();

			if (t - bucket_start >= 1.0) {
				unsigned long long r =
					(unsigned long long)(bucket_msgs / (t - bucket_start));

				if (r > peak_msgs_per_s)
					peak_msgs_per_s = r;
				bucket_msgs = 0;
				bucket_start = t;
			}
		}

		for (i = 0; i < spin; i++)
			(void)rand();
	}

	t_end = now_s();
	close(fd);

	{
		double dur = t_end - t_start;

		if (dur <= 0)
			dur = 1e-9;
		printf("FTCLIENT tag=%s\n", tag);
		printf("FTCLIENT msg_size=%d spin=%d\n", msg_size, spin);
		printf("FTCLIENT duration_s=%.6f\n", dur);
		printf("FTCLIENT sent_msgs=%llu\n", sent_msgs);
		printf("FTCLIENT sent_bytes=%llu\n", sent_bytes);
		printf("FTCLIENT short_sends=%llu\n", short_sends);
		printf("FTCLIENT stuck_sends=%llu\n", stuck_sends);
		printf("FTCLIENT send_mbps=%.3f\n", sent_bytes * 8.0 / 1e6 / dur);
		printf("FTCLIENT send_msgs_per_s=%.1f\n", sent_msgs / dur);
		printf("FTCLIENT send_msgs_per_s_peak=%llu\n", peak_msgs_per_s);
		fflush(stdout);
	}
	free(msg);
	return 0;
}
