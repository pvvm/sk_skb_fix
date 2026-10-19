/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fix_test receiver: the q1 loader cut down to the SK_SKB hook, no replies,
 * and BPF_STATS_RUN_TIME always on -- time inside the parser and verdict per
 * delivered message is the measurement.
 *
 * Output: every number the harness parses is on a line starting "FTRESULT ",
 * as key=value. Nothing else is machine-read.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "fix_test_common.h"

#define PKT_SIZE	(64 * 1024)

static volatile sig_atomic_t stop;

static void on_sigint(int sig) { (void)sig; stop = 1; }

struct opts {
	const char	*obj;
	int		style, area, mode;
	int		msg_size;
	int		warmup, measure;
	int		cpu;
	int		accept_wait;
	int		verify;		/* 0 off, 1 sample, 2 full */
	int		sample;
	bool		dry_run;	/* verify + attach nothing, then exit */
	const char	*tag;
};

static const char *const styles[] = { "", "pull", "load", "dynptr" };
static const char *const areas[]  = { "header", "half", "full" };
static const char *const modes[]  = { "ro", "rw" };
static const char *const verifs[] = { "off", "sample", "full" };

static void usage(const char *a0)
{
	fprintf(stderr,
"Usage: %s [options]\n"
"  --style pull|load|dynptr   how the verdict reaches the bytes (default pull)\n"
"  --area header|half|full    how much of each message it touches (default full)\n"
"  --mode ro|rw               rw also writes one byte, observably (default ro)\n"
"  --msg-size N               wire bytes per message; must match the client\n"
"  --warmup N                 seconds before the measurement window (default 3)\n"
"  --measure N                seconds of measurement window         (default 5)\n"
"  --cpu N|none               pin the reader                        (default 18)\n"
"  --accept-wait N            seconds to wait for the client        (default 30)\n"
"  --verify off|sample|full   check the delivered bytes             (default sample)\n"
"  --sample K                 check one message in K when sampling  (default 64)\n"
"  --tag S                    copied into the FTRESULT block\n"
"  --obj FILE                 BPF object          (default build/fix_test.bpf.o)\n"
"  --dry-run                  load and verify the programs, then exit\n",
		a0);
}

static int parse_enum(const char *s, const char *const *names, int n,
		      const char *what)
{
	int i;

	for (i = 0; i < n; i++)
		if (names[i][0] && !strcmp(s, names[i]))
			return i;
	fprintf(stderr, "unknown %s: \"%s\"\n", what, s);
	exit(2);
}

struct ft_stats_kern {
	__u64 v[ST_MAX];
};

/* All counters live in ONE per-CPU map value: fetch it per CPU, sum one field. */
static __u64 stat_read(int fd, __u32 key, int ncpu)
{
	static struct ft_stats_kern vals[1024];
	__u32 zero = 0;
	__u64 sum = 0;
	int i;

	if (ncpu > (int)(sizeof(vals) / sizeof(vals[0])))
		ncpu = sizeof(vals) / sizeof(vals[0]);
	if (key >= ST_MAX)
		return 0;
	if (bpf_map_lookup_elem(fd, &zero, vals))
		return 0;
	for (i = 0; i < ncpu; i++)
		sum += vals[i].v[key];
	return sum;
}

static double now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Time spent inside one BPF program, and how many times it ran. */
struct prog_stat { __u64 ns, cnt; };

static int read_prog_stat(int prog_fd, struct prog_stat *out)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);

	if (bpf_prog_get_info_by_fd(prog_fd, &info, &len))
		return -1;
	out->ns  = info.run_time_ns;
	out->cnt = info.run_cnt;
	return 0;
}

int main(int argc, char **argv)
{
	static const char *const stat_names[] = FT_STAT_NAMES;

	struct opts o = {
		.obj = "build/fix_test.bpf.o", .style = FT_STYLE_PULL,
		.area = FT_AREA_FULL, .mode = FT_RO, .msg_size = 128,
		.warmup = 3, .measure = 5, .cpu = 18, .accept_wait = 30,
		.verify = 1, .sample = 64, .tag = "",
	};
	struct ft_cfg cfg = { .sentinel = FT_SENTINEL };
	struct bpf_object *obj = NULL;
	struct bpf_program *p, *p_parser = NULL, *p_verdict = NULL;
	struct bpf_map *m_rodata = NULL, *m;
	const char *parser_name = "ft_skskb_parser";
	char verdict_name[64];
	int err = 1, ncpu = 1, stats_fd = -1, sock_fd = -1, stats_en_fd = -1;
	int srv = -1, cli = -1;
	__u32 zero = 0;
	void *rodata;
	size_t rodata_sz;

	{
		enum {
			O_STYLE = 1000, O_AREA, O_MODE, O_MSG, O_WARM, O_MEAS,
			O_CPU, O_AWAIT, O_VERIFY, O_SAMPLE, O_TAG, O_OBJ, O_DRY,
			O_HELP
		};
		static const struct option lo[] = {
			{ "style",       required_argument, NULL, O_STYLE  },
			{ "area",        required_argument, NULL, O_AREA   },
			{ "mode",        required_argument, NULL, O_MODE   },
			{ "msg-size",    required_argument, NULL, O_MSG    },
			{ "warmup",      required_argument, NULL, O_WARM   },
			{ "measure",     required_argument, NULL, O_MEAS   },
			{ "cpu",         required_argument, NULL, O_CPU    },
			{ "accept-wait", required_argument, NULL, O_AWAIT  },
			{ "verify",      required_argument, NULL, O_VERIFY },
			{ "sample",      required_argument, NULL, O_SAMPLE },
			{ "tag",         required_argument, NULL, O_TAG    },
			{ "obj",         required_argument, NULL, O_OBJ    },
			{ "dry-run",     no_argument,       NULL, O_DRY    },
			{ "help",        no_argument,       NULL, O_HELP   },
			{ NULL, 0, NULL, 0 }
		};
		int c;

		while ((c = getopt_long(argc, argv, "h", lo, NULL)) != -1) {
			switch (c) {
			case O_STYLE: o.style = parse_enum(optarg, styles, 4, "style"); break;
			case O_AREA:  o.area  = parse_enum(optarg, areas, 3, "area"); break;
			case O_MODE:  o.mode  = parse_enum(optarg, modes, 2, "mode"); break;
			case O_VERIFY:o.verify= parse_enum(optarg, verifs, 3, "verify"); break;
			case O_MSG:   o.msg_size = atoi(optarg); break;
			case O_WARM:  o.warmup = atoi(optarg); break;
			case O_MEAS:  o.measure = atoi(optarg); break;
			case O_SAMPLE:o.sample = atoi(optarg); break;
			case O_AWAIT: o.accept_wait = atoi(optarg); break;
			case O_CPU:   o.cpu = strcmp(optarg, "none") ? atoi(optarg) : -1; break;
			case O_TAG:   o.tag = optarg; break;
			case O_OBJ:   o.obj = optarg; break;
			case O_DRY:   o.dry_run = true; break;
			default:      usage(argv[0]); return c == O_HELP ? 0 : 2;
			}
		}
	}

	if (o.sample < 1)
		o.sample = 1;

	if (o.msg_size < 2 * FT_HEAD_SIZE || o.msg_size > FT_ACCESS_MAX) {
		fprintf(stderr, "--msg-size %d is outside [%d, %d]\n",
			o.msg_size, 2 * FT_HEAD_SIZE, FT_ACCESS_MAX);
		return 2;
	}

	cfg.style      = o.style;
	cfg.area       = o.area;
	cfg.mode       = o.mode;
	cfg.msg_size   = o.msg_size;
	cfg.access_len = ft_access_len(o.msg_size, o.area);
	cfg.wr_off     = ft_wr_off(cfg.access_len);

	if (o.cpu >= 0) {
		cpu_set_t set;

		CPU_ZERO(&set);
		CPU_SET(o.cpu, &set);
		if (sched_setaffinity(0, sizeof(set), &set))
			fprintf(stderr, "sched_setaffinity(%d): %s\n",
				o.cpu, strerror(errno));
	}

	signal(SIGINT, on_sigint);
	signal(SIGPIPE, SIG_IGN);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	obj = bpf_object__open_file(o.obj, NULL);
	if (!obj) {
		fprintf(stderr, "open %s: %s\n", o.obj, strerror(errno));
		return 1;
	}

	/* .rodata carries struct ft_cfg. Setting it BEFORE load is what makes
	 * every field a verifier constant.
	 */
	bpf_object__for_each_map(m, obj) {
		const char *n = bpf_map__name(m);

		if (n && strstr(n, ".rodata") && !strstr(n, ".str")) {
			m_rodata = m;
			break;
		}
	}
	if (!m_rodata) {
		fprintf(stderr, "no .rodata map in %s\n", o.obj);
		goto out;
	}
	rodata = bpf_map__initial_value(m_rodata, &rodata_sz);
	if (!rodata || rodata_sz < sizeof(cfg)) {
		fprintf(stderr, ".rodata is %zu bytes, need %zu\n",
			rodata_sz, sizeof(cfg));
		goto out;
	}
	memcpy(rodata, &cfg, sizeof(cfg));

	snprintf(verdict_name, sizeof(verdict_name), "ft_verdict_%s_%s",
		 styles[o.style], modes[o.mode]);

	/* Autoload exactly the two programs this cell needs: loading a
	 * writing verdict the cell does not use would still be verified, and
	 * the others are dead weight.
	 */
	bpf_object__for_each_program(p, obj) {
		const char *n = bpf_program__name(p);
		bool want = !strcmp(n, parser_name) || !strcmp(n, verdict_name);

		bpf_program__set_autoload(p, want);
		if (!want)
			continue;
		if (!strcmp(n, parser_name))
			p_parser = p;
		else
			p_verdict = p;
	}
	if (!p_parser || !p_verdict) {
		fprintf(stderr, "object has no %s / %s\n", parser_name, verdict_name);
		goto out;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "load failed for %s + %s: %s\n",
			parser_name, verdict_name, strerror(errno));
		goto out;
	}

	ncpu = libbpf_num_possible_cpus();
	m = bpf_object__find_map_by_name(obj, "stats");
	stats_fd = m ? bpf_map__fd(m) : -1;
	m = bpf_object__find_map_by_name(obj, "sock_map_rx");
	sock_fd = m ? bpf_map__fd(m) : -1;
	if (stats_fd < 0 || sock_fd < 0) {
		fprintf(stderr, "missing stats or sock_map_rx\n");
		goto out;
	}

	/* The syscall form, not the sysctl: it is refcounted and tied to this
	 * fd, so the counters go off again when this process exits however it
	 * exits.
	 */
	stats_en_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
	if (stats_en_fd < 0)
		fprintf(stderr, "bpf_enable_stats: %s (run-time stats will read "
				"zero)\n", strerror(errno));

	{
		/* Per-run provenance: kernel build, boot, BPF object. */
		struct utsname un;
		FILE *bf, *sp;
		char bid[64] = "unknown";
		char sha[128] = "";
		char cmd[512];

		if (!uname(&un))
			printf("FTRESULT kernel_build=%s\n", un.version);
		bf = fopen("/proc/sys/kernel/random/boot_id", "r");
		if (bf) {
			if (fgets(bid, sizeof(bid), bf)) {
				char *nl = strchr(bid, '\n');

				if (nl)
					*nl = '\0';
			}
			fclose(bf);
		}
		printf("FTRESULT boot_id=%s\n", bid);

		snprintf(cmd, sizeof(cmd), "sha256sum '%s' 2>/dev/null | cut -c1-16", o.obj);
		sp = popen(cmd, "r");
		if (sp) {
			if (fgets(sha, sizeof(sha), sp)) {
				char *nl = strchr(sha, '\n');

				if (nl)
					*nl = '\0';
				printf("FTRESULT bpf_obj_sha=%s\n", sha);
			}
			pclose(sp);
		}
	}

	printf("cell: style=%s area=%s mode=%s msg_size=%d access_len=%u wr_off=%u\n",
	       styles[o.style], areas[o.area], modes[o.mode], o.msg_size,
	       cfg.access_len, cfg.wr_off);
	printf("programs: %s + %s (verified)\n", parser_name, verdict_name);

	if (o.dry_run) {
		printf("FTRESULT dry_run=ok\n");
		err = 0;
		goto out;
	}

	/* --- socket ------------------------------------------------------ */
	srv = socket(AF_INET, SOCK_STREAM, 0);
	if (srv < 0) { perror("socket"); goto out; }
	{
		int on = 1;
		struct sockaddr_in a = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = INADDR_ANY,
			.sin_port = htons(FT_PORT),
		};

		setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		if (bind(srv, (struct sockaddr *)&a, sizeof(a))) {
			perror("bind"); goto out;
		}
	}
	listen(srv, 8);
	printf("listening on %d, accept window %d s\n", FT_PORT, o.accept_wait);
	fflush(stdout);

	{
		struct pollfd pfd = { .fd = srv, .events = POLLIN };
		int r = poll(&pfd, 1, o.accept_wait * 1000);

		if (r <= 0) {
			fprintf(stderr, "no client within %d s\n", o.accept_wait);
			goto out;
		}
		cli = accept(srv, NULL, NULL);
		if (cli < 0) { perror("accept"); goto out; }
	}

	/* Before the sockmap attach, so it is in force for the first byte the
	 * hook sees. SO_RCVBUF also locks the buffer, which turns autotuning
	 * off. Read back and printed: a clamped request is otherwise
	 * indistinguishable from an honoured one.
	 */
	{
		int v = FT_RCVBUF, rb = 0;
		socklen_t rl = sizeof(rb);

		if (setsockopt(cli, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v)))
			fprintf(stderr, "setsockopt(SO_RCVBUF, %d): %s\n",
				v, strerror(errno));
		if (!getsockopt(cli, SOL_SOCKET, SO_RCVBUF, &rb, &rl))
			printf("FTRESULT rcvbuf_before_attach=%d\n", rb);
	}

	if (bpf_prog_attach(bpf_program__fd(p_verdict), sock_fd,
			    BPF_SK_SKB_STREAM_VERDICT, 0)) {
		fprintf(stderr, "attach verdict: %s\n", strerror(errno));
		goto out;
	}
	if (bpf_prog_attach(bpf_program__fd(p_parser), sock_fd,
			    BPF_SK_SKB_STREAM_PARSER, 0)) {
		fprintf(stderr, "attach parser: %s\n", strerror(errno));
		goto out;
	}
	if (bpf_map_update_elem(sock_fd, &zero, &cli, BPF_NOEXIST)) {
		fprintf(stderr, "sockmap insert: %s\n", strerror(errno));
		goto out;
	}
	{
		int rb = 0;
		socklen_t rl = sizeof(rb);

		if (!getsockopt(cli, SOL_SOCKET, SO_RCVBUF, &rb, &rl))
			printf("FTRESULT rcvbuf_after_attach=%d\n", rb);
	}

	/* --- receive ----------------------------------------------------- */
	{
		static unsigned char buf[PKT_SIZE];
		struct pollfd pfd = { .fd = cli, .events = POLLIN };
		double t0 = now_s(), t_meas_start = 0, t_meas_end = 0;
		unsigned long long bytes = 0, bytes_at_start = 0;
		unsigned long long frame_bad = 0, sent_bad = 0, checked = 0;
		/* Deepest receive queue seen in the window (FIONREAD). */
		int inq_max = 0, inq_end = 0;
		unsigned int inq_tick = 0;
		__u64 base[ST_MAX] = {0};
		struct prog_stat ps0 = {0}, pv0 = {0}, ps1 = {0}, pv1 = {0};
		bool measuring = false, done = false;
		int i, fl = fcntl(cli, F_GETFL, 0);

		fcntl(cli, F_SETFL, fl | O_NONBLOCK);

		printf("FTRESULT phase=warmup seconds=%d\n", o.warmup);
		fflush(stdout);

		while (!stop && !done) {
			double t = now_s() - t0;
			int n;

			if (!measuring && t >= o.warmup) {
				measuring = true;
				t_meas_start = now_s();
				bytes_at_start = bytes;
				for (i = 0; i < ST_MAX; i++)
					base[i] = stat_read(stats_fd, i, ncpu);
				read_prog_stat(bpf_program__fd(p_parser), &ps0);
				read_prog_stat(bpf_program__fd(p_verdict), &pv0);
				printf("FTRESULT phase=measure seconds=%d\n", o.measure);
				fflush(stdout);
			}
			if (measuring && now_s() - t_meas_start >= o.measure) {
				t_meas_end = now_s();
				done = true;
				break;
			}

			/* One ioctl per 256 polls: often enough to catch a queue
			 * building, rarely enough not to show in the measurement.
			 */
			if (measuring && ((inq_tick++ & 0xFF) == 0)) {
				int q = 0;

				if (!ioctl(cli, FIONREAD, &q) && q > inq_max)
					inq_max = q;
			}

			if (poll(&pfd, 1, 100) <= 0)
				continue;
			if (!(pfd.revents & POLLIN))
				break;

			while (!stop) {
				/* Under a backlog recv() never returns EAGAIN, so
				 * both window edges are checked here too, or the
				 * window would open late and close whenever the
				 * sender stops.
				 */
				if (!measuring && now_s() - t0 >= o.warmup)
					break;
				if (measuring && now_s() - t_meas_start >= o.measure) {
					t_meas_end = now_s();
					done = true;
					break;
				}

				n = recv(cli, buf, sizeof(buf), 0);
				if (n < 0) {
					if (errno == EAGAIN || errno == EWOULDBLOCK)
						break;
					if (errno == EINTR)
						continue;
					fprintf(stderr, "recv: %s\n", strerror(errno));
					done = true;
					break;
				}
				if (n == 0) { done = true; break; }

				/* Framing and sentinel check. Message k is stream
				 * bytes [k*S, (k+1)*S). Byte 0 of every message
				 * must still be 'Q', and in RW mode the byte at
				 * wr_off must be the sentinel.
				 */
				if (o.verify) {
					unsigned long long s0 = bytes, s1 = bytes + n;
					unsigned long long k = s0 / o.msg_size;

					/* Start one message EARLIER: a message that
					 * began in the previous recv() can carry its
					 * sentinel into this one.
					 */
					if (k)
						k--;

					for (; k * (unsigned long long)o.msg_size < s1; k++) {
						unsigned long long fb = k * o.msg_size;
						unsigned long long sb = fb + cfg.wr_off;

						if (o.verify == 1 && (k % o.sample))
							continue;

						if (fb >= s0 && fb < s1) {
							unsigned char want =
								(o.mode == FT_RW && cfg.wr_off == 0)
								? (unsigned char)FT_SENTINEL : 'Q';

							checked++;
							if (buf[fb - s0] != want)
								frame_bad++;
						}
						if (o.mode == FT_RW && cfg.wr_off != 0 &&
						    sb >= s0 && sb < s1) {
							if (buf[sb - s0] != (unsigned char)FT_SENTINEL)
								sent_bad++;
						}
					}
				}

				bytes += n;
			}
		}

		if (ioctl(cli, FIONREAD, &inq_end))
			inq_end = -1;
		if (inq_end > inq_max)
			inq_max = inq_end;

		if (!t_meas_end)
			t_meas_end = now_s();

		/* Interrupted before the window opened: report an empty window
		 * rather than divide the warmup by a duration from zero.
		 */
		if (!measuring) {
			t_meas_start = t_meas_end;
			bytes_at_start = bytes;
		}
		printf("FTRESULT measured=%s\n", measuring ? "yes" : "no");

		{
			double dur = t_meas_end - t_meas_start;
			unsigned long long dbytes = bytes - bytes_at_start;
			unsigned long long dmsgs = dbytes / o.msg_size;
			__u64 d[ST_MAX];

			for (i = 0; i < ST_MAX; i++)
				d[i] = stat_read(stats_fd, i, ncpu) - base[i];
			read_prog_stat(bpf_program__fd(p_parser), &ps1);
			read_prog_stat(bpf_program__fd(p_verdict), &pv1);

			if (dur <= 0)
				dur = 1e-9;

			printf("FTRESULT tag=%s\n", o.tag);
			printf("FTRESULT hook=skskb style=%s area=%s mode=%s work=none\n",
			       styles[o.style], areas[o.area], modes[o.mode]);
			printf("FTRESULT msg_size=%d access_len=%u wr_off=%u\n",
			       o.msg_size, cfg.access_len, cfg.wr_off);
			printf("FTRESULT duration_s=%.6f\n", dur);
			printf("FTRESULT bytes=%llu\n", dbytes);
			printf("FTRESULT msgs=%llu\n", dmsgs);
			printf("FTRESULT mbps=%.3f\n", dbytes * 8.0 / 1e6 / dur);
			printf("FTRESULT msgs_per_s=%.1f\n", dmsgs / dur);
			for (i = 0; i < ST_MAX; i++)
				printf("FTRESULT st_%s=%llu\n", stat_names[i],
				       (unsigned long long)d[i]);
			if (dmsgs) {
				__u64 inv = (stats_en_fd >= 0 && pv1.cnt > pv0.cnt)
					    ? (pv1.cnt - pv0.cnt) : d[ST_RUN_CALLS];

				printf("FTRESULT invocations_per_msg=%.4f\n",
				       (double)inv / dmsgs);
				printf("FTRESULT access_bytes_per_msg=%.2f\n",
				       (double)d[ST_ACCESS_BYTES] / dmsgs);
			}
			printf("FTRESULT inq_max=%d\n", inq_max);
			printf("FTRESULT inq_end=%d\n", inq_end);
			printf("FTRESULT bpf_stats=%s\n", stats_en_fd >= 0 ? "on" : "off");
			if (stats_en_fd >= 0) {
				__u64 pns = ps1.ns - ps0.ns, pcnt = ps1.cnt - ps0.cnt;
				__u64 vns = pv1.ns - pv0.ns, vcnt = pv1.cnt - pv0.cnt;

				printf("FTRESULT bpf_parser_ns=%llu\n", (unsigned long long)pns);
				printf("FTRESULT bpf_parser_runs=%llu\n", (unsigned long long)pcnt);
				printf("FTRESULT bpf_verdict_ns=%llu\n", (unsigned long long)vns);
				printf("FTRESULT bpf_verdict_runs=%llu\n", (unsigned long long)vcnt);
				if (dmsgs) {
					/* The measurement: time inside parser +
					 * verdict per delivered message.
					 */
					printf("FTRESULT bpf_ns_per_msg=%.3f\n",
					       (double)(pns + vns) / dmsgs);
					printf("FTRESULT bpf_verdict_ns_per_msg=%.3f\n",
					       (double)vns / dmsgs);
				}
				if (vcnt)
					printf("FTRESULT bpf_verdict_ns_per_run=%.3f\n",
					       (double)vns / vcnt);
			}
			printf("FTRESULT verify_mode=%s\n", verifs[o.verify]);
			printf("FTRESULT verify_checked=%llu\n", checked);
			printf("FTRESULT verify_frame_bad=%llu\n", frame_bad);
			printf("FTRESULT verify_sentinel_bad=%llu\n", sent_bad);

			/* One line the harness greps to decide whether a run is
			 * usable. A frame or sentinel mismatch means bytes were
			 * delivered untransformed or transformed in the wrong
			 * place; a failed write means RO wearing RW's label.
			 */
			{
				double rf_ppm = dmsgs ? 1e6 * (double)d[ST_RESYNC_FAIL] / dmsgs : 0;

				printf("FTRESULT resync_fail_ppm=%.1f\n", rf_ppm);
				printf("FTRESULT valid=%s\n",
				       (measuring && dmsgs > 0 &&
					frame_bad == 0 && sent_bad == 0 &&
					rf_ppm < 1000.0 &&
					d[ST_ERR] == 0 && d[ST_WR_FAIL] == 0 &&
					d[ST_DYN_NULL] == 0 && d[ST_PARSE_ERR] == 0 &&
					(o.mode == FT_RO || d[ST_WR_OK] > 0))
				       ? "yes" : "NO");
			}
			fflush(stdout);
		}
		err = 0;
	}

out:
	if (sock_fd >= 0)
		bpf_map_delete_elem(sock_fd, &zero);
	/* Abortive close (RST). tcp_close() only resets the peer when
	 * sk_receive_queue still holds unread data, and strparser has already
	 * moved the backlog into psock->ingress_msg -- so a plain close sends a
	 * FIN and the client sits in send() against a zero window until its
	 * 10 s stuck-send limit. Nothing is measured after this point.
	 */
	if (cli >= 0) {
		struct linger lg = { .l_onoff = 1, .l_linger = 0 };

		setsockopt(cli, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
		close(cli);
	}
	if (srv >= 0)
		close(srv);
	if (obj)
		bpf_object__close(obj);
	if (stats_en_fd >= 0)
		close(stats_en_fd);
	return err;
}
