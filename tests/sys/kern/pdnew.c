/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 John Ericson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Tests for the embryonic-process model: pdrfork(RFEMBRYO), pdsetfd(),
 * and pdexec().  A pdexec() with no flags loads the image and runs it,
 * so these need no pdstart(); that, and the rest of the family, are
 * exercised separately.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/procdesc.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

/*
 * Helper: open an executable by path and return the fd.
 */
static int
open_exec(const char *path)
{
	int fd;

	/*
	 * O_RDONLY, not O_EXEC: exec-by-fd checks the file's execute
	 * permission, not the descriptor's access mode, and a shebang
	 * interpreter must be able to read the script back through
	 * /dev/fd/N -- which requires a readable descriptor.
	 */
	fd = open(path, O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "open(%s): %s", path, strerror(errno));
	return (fd);
}

/*
 * Create an embryonic process with pdrfork(2) and RFEMBRYO, returning its
 * process descriptor.  The process has no image yet; a pdexec(2) gives it
 * one and, with no flags, runs it.
 */
static int
pdembryo(void)
{
	int procfd;
	pid_t pid;

	pid = pdrfork(&procfd, 0, RFEMBRYO);
	ATF_REQUIRE_MSG(pid > 0, "pdrfork(RFEMBRYO): %s", strerror(errno));
	return (procfd);
}

/*
 * Basic lifecycle: create, exec, wait.  Run /usr/bin/true, exit status 0.
 */
ATF_TC_WITHOUT_HEAD(basic_true);
ATF_TC_BODY(basic_true, tc)
{
	char *argv[] = { __DECONST(char *, "true"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status;

	execfd = open_exec("/usr/bin/true");
	procfd = pdembryo();

	error = pdexec(procfd, execfd, argv, envv, 0);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	close(execfd);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "unexpected exit status: %#x", status);

	close(procfd);
}

/*
 * Run /usr/bin/false and verify exit status 1.
 */
ATF_TC_WITHOUT_HEAD(basic_false);
ATF_TC_BODY(basic_false, tc)
{
	char *argv[] = { __DECONST(char *, "false"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status;

	execfd = open_exec("/usr/bin/false");
	procfd = pdembryo();

	error = pdexec(procfd, execfd, argv, envv, 0);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	close(execfd);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 1,
	    "unexpected exit status: %#x", status);

	close(procfd);
}

/*
 * Install stdout with pdsetfd(2) before the exec, and read the output.
 */
ATF_TC_WITHOUT_HEAD(setfd_stdout);
ATF_TC_BODY(setfd_stdout, tc)
{
	char buf[128];
	char *argv[] = { __DECONST(char *, "echo"),
	    __DECONST(char *, "hello"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status, pipefd[2];
	ssize_t n;

	ATF_REQUIRE(pipe(pipefd) == 0);
	execfd = open_exec("/bin/echo");
	procfd = pdembryo();

	error = pdsetfd(procfd, STDOUT_FILENO, pipefd[1]);
	ATF_REQUIRE_MSG(error == 0, "pdsetfd: %s", strerror(errno));
	close(pipefd[1]);

	error = pdexec(procfd, execfd, argv, envv, 0);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	close(execfd);

	n = read(pipefd[0], buf, sizeof(buf) - 1);
	ATF_REQUIRE_MSG(n > 0, "read: %s", strerror(errno));
	buf[n] = '\0';
	ATF_REQUIRE_MSG(strcmp(buf, "hello\n") == 0,
	    "unexpected output: '%s'", buf);
	close(pipefd[0]);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	close(procfd);
}

/*
 * Install stdin and stdout with pdsetfd(2), pipe data through /bin/cat.
 */
ATF_TC_WITHOUT_HEAD(setfd_stdin);
ATF_TC_BODY(setfd_stdin, tc)
{
	char buf[128];
	char *argv[] = { __DECONST(char *, "cat"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status, in_pipe[2], out_pipe[2];
	ssize_t n;

	ATF_REQUIRE(pipe(in_pipe) == 0);
	ATF_REQUIRE(pipe(out_pipe) == 0);
	execfd = open_exec("/bin/cat");
	procfd = pdembryo();

	error = pdsetfd(procfd, STDIN_FILENO, in_pipe[0]);
	ATF_REQUIRE_MSG(error == 0, "pdsetfd stdin: %s", strerror(errno));
	close(in_pipe[0]);
	error = pdsetfd(procfd, STDOUT_FILENO, out_pipe[1]);
	ATF_REQUIRE_MSG(error == 0, "pdsetfd stdout: %s", strerror(errno));
	close(out_pipe[1]);

	error = pdexec(procfd, execfd, argv, envv, 0);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	close(execfd);

	ATF_REQUIRE(write(in_pipe[1], "world\n", 6) == 6);
	close(in_pipe[1]);

	n = read(out_pipe[0], buf, sizeof(buf) - 1);
	ATF_REQUIRE_MSG(n > 0, "read: %s", strerror(errno));
	buf[n] = '\0';
	ATF_REQUIRE_MSG(strcmp(buf, "world\n") == 0,
	    "unexpected output: '%s'", buf);
	close(out_pipe[0]);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	close(procfd);
}

/*
 * A file that is executable but has no recognized format fails with ENOEXEC.
 */
ATF_TC_WITHOUT_HEAD(error_noexec);
ATF_TC_BODY(error_noexec, tc)
{
	char *argv[] = { __DECONST(char *, "noexec"), NULL };
	char *envv[] = { NULL };
	char path[] = "/tmp/pdnew_noexec.XXXXXX";
	int error, fd, procfd, tmpfd;

	tmpfd = mkstemp(path);
	ATF_REQUIRE_MSG(tmpfd >= 0, "mkstemp: %s", strerror(errno));
	ATF_REQUIRE(write(tmpfd, "not an executable\n", 18) == 18);
	ATF_REQUIRE(fchmod(tmpfd, 0755) == 0);
	close(tmpfd);

	fd = open_exec(path);
	procfd = pdembryo();

	error = pdexec(procfd, fd, argv, envv, 0);
	ATF_REQUIRE_MSG(error == -1, "pdexec should have failed");
	ATF_REQUIRE_MSG(errno == ENOEXEC,
	    "unexpected errno: %d (%s)", errno, strerror(errno));

	close(procfd);
	close(fd);
	unlink(path);
}

/*
 * pdexec(2) with an invalid process descriptor fails with EBADF.
 */
ATF_TC_WITHOUT_HEAD(error_bad_procfd);
ATF_TC_BODY(error_bad_procfd, tc)
{
	char *argv[] = { __DECONST(char *, "true"), NULL };
	char *envv[] = { NULL };
	int error, execfd;

	execfd = open_exec("/usr/bin/true");
	error = pdexec(999, execfd, argv, envv, 0);
	ATF_REQUIRE_MSG(error == -1, "pdexec should have failed");
	ATF_REQUIRE_MSG(errno == EBADF,
	    "unexpected errno: %d (%s)", errno, strerror(errno));
	close(execfd);
}

/*
 * Closing the descriptor of an embryo that was never given an image
 * destroys it; its pid must name neither a live process nor a zombie.
 */
ATF_TC_WITHOUT_HEAD(close_before_exec);
ATF_TC_BODY(close_before_exec, tc)
{
	int error, procfd;
	pid_t pid;

	procfd = pdembryo();

	error = pdgetpid(procfd, &pid);
	ATF_REQUIRE_MSG(error == 0, "pdgetpid: %s", strerror(errno));
	ATF_REQUIRE(pid > 0);

	close(procfd);

	ATF_REQUIRE_MSG(kill(pid, 0) == -1 && errno == ESRCH,
	    "embryo pid %d still present after close (kill: %s)",
	    (int)pid, strerror(errno));
}

/*
 * pdsetfd(2) replacing an already-set descriptor: the last one wins.
 */
ATF_TC_WITHOUT_HEAD(setfd_replace);
ATF_TC_BODY(setfd_replace, tc)
{
	char buf[128];
	char *argv[] = { __DECONST(char *, "echo"),
	    __DECONST(char *, "replaced"), NULL };
	char *envv[] = { NULL };
	int error, execfd, procfd, status, pipe1[2], pipe2[2];
	ssize_t n;

	ATF_REQUIRE(pipe(pipe1) == 0);
	ATF_REQUIRE(pipe(pipe2) == 0);
	execfd = open_exec("/bin/echo");
	procfd = pdembryo();

	error = pdsetfd(procfd, STDOUT_FILENO, pipe1[1]);
	ATF_REQUIRE_MSG(error == 0, "pdsetfd 1: %s", strerror(errno));
	error = pdsetfd(procfd, STDOUT_FILENO, pipe2[1]);
	ATF_REQUIRE_MSG(error == 0, "pdsetfd 2: %s", strerror(errno));
	close(pipe1[1]);
	close(pipe2[1]);

	error = pdexec(procfd, execfd, argv, envv, 0);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	close(execfd);

	n = read(pipe1[0], buf, sizeof(buf));
	ATF_REQUIRE_MSG(n == 0, "pipe1 should be empty, got %zd bytes", n);
	close(pipe1[0]);

	n = read(pipe2[0], buf, sizeof(buf) - 1);
	ATF_REQUIRE_MSG(n > 0, "read pipe2: %s", strerror(errno));
	buf[n] = '\0';
	ATF_REQUIRE_MSG(strcmp(buf, "replaced\n") == 0,
	    "unexpected output: '%s'", buf);
	close(pipe2[0]);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE(error == 0);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	close(procfd);
}

/*
 * A shebang script exec'd by descriptor: its interpreter reaches the script
 * through /dev/fd/N, so fdescfs must be mounted; skip otherwise.
 */
ATF_TC_WITHOUT_HEAD(shebang);
ATF_TC_BODY(shebang, tc)
{
	char buf[128];
	char *argv[] = { __DECONST(char *, "testscript"), NULL };
	char *envv[] = { NULL };
	char scriptpath[] = "/tmp/pdnew_test.XXXXXX";
	int error, execfd, procfd, scriptfd, status, pipefd[2];
	ssize_t n;
	struct statfs sf;

	if (statfs("/dev/fd", &sf) != 0 ||
	    strcmp(sf.f_fstypename, "fdescfs") != 0)
		atf_tc_skip("fdescfs is not mounted at /dev/fd");

	scriptfd = mkstemp(scriptpath);
	ATF_REQUIRE_MSG(scriptfd >= 0, "mkstemp: %s", strerror(errno));
	ATF_REQUIRE(write(scriptfd, "#!/bin/sh\necho shebang\n", 23) == 23);
	ATF_REQUIRE(fchmod(scriptfd, 0755) == 0);
	close(scriptfd);

	ATF_REQUIRE(pipe(pipefd) == 0);
	execfd = open_exec(scriptpath);
	procfd = pdembryo();

	error = pdsetfd(procfd, STDOUT_FILENO, pipefd[1]);
	ATF_REQUIRE_MSG(error == 0, "pdsetfd: %s", strerror(errno));
	close(pipefd[1]);

	error = pdexec(procfd, execfd, argv, envv, 0);
	ATF_REQUIRE_MSG(error == 0, "pdexec: %s", strerror(errno));
	close(execfd);

	n = read(pipefd[0], buf, sizeof(buf) - 1);
	ATF_REQUIRE_MSG(n > 0, "read: %s", strerror(errno));
	buf[n] = '\0';
	ATF_REQUIRE_MSG(strcmp(buf, "shebang\n") == 0,
	    "unexpected output: '%s'", buf);
	close(pipefd[0]);

	error = pdwait(procfd, &status, WEXITED, NULL, NULL);
	ATF_REQUIRE_MSG(error == 0, "pdwait: %s", strerror(errno));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	close(procfd);
	unlink(scriptpath);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, basic_true);
	ATF_TP_ADD_TC(tp, basic_false);
	ATF_TP_ADD_TC(tp, setfd_stdout);
	ATF_TP_ADD_TC(tp, setfd_stdin);
	ATF_TP_ADD_TC(tp, error_noexec);
	ATF_TP_ADD_TC(tp, error_bad_procfd);
	ATF_TP_ADD_TC(tp, close_before_exec);
	ATF_TP_ADD_TC(tp, setfd_replace);
	ATF_TP_ADD_TC(tp, shebang);

	return (atf_no_error());
}
