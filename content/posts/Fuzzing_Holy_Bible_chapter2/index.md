---
title: "LibAFL Fuzzing Holy Bible - Chapter II: Fuzzing Libexif - CVE-2009-3895 & CVE-2012-2836"
date: 2023-11-27
draft: false
summary: "Using LibAFL fuzzer to reproduce CVE-2009-3895 & CVE-2012-2836"
tags: ["libafl"]
output: 
  html_document:
    toc: true
    toc_float:
      collapsed: true
    toc_depth: 3
    number_sections: true
---
-------------
###### tags: `libafl`


### Background
[Antonio Morales](https://twitter.com/nosoynadiemas?lang=en) đã tạo một cái repo [Fuzzing 101](https://github.com/antonio-morales/Fuzzing101) với mục đích là tạo ra các challenge liên quan đến những kiến thức và basic skill của fuzzing dành cho những ai muốn học nó và sử dụng nó để tìm ra các vulnerabilities. Repo này tập trung vào cách sử dụng của AFL++ nhưng trong series mình viết với mục đích là solve những challenge sử dụng LibAFL thay vì là AFL++.  

Trong series này thì mình sẽ tìm hiểu các thư viện và viết fuzzers bằng ngôn ngữ Rust, mình sẽ cố gắng solve các challenges gần giống với solution nhất mà mình có thể làm được. 

Và trong series này mình sẽ sử dụng ngôn ngữ Rust để viết fuzzers. Nếu như bạn chưa biết Rust và Fuzzers là gì thì mình khuyến khích bạn nên tìm hiểu về nó trước khi đọc những gì tiếp theo.

### About LibAFL

LibAFL là một sự cải tiến từ AFL++ được viết bằng ngôn ngữ Rust. Nó nhanh hơn, đa dạng nền tảng, no_std compatibles và nó tận dụng tốt nguồn tài nguyên của máy. 

Để hiểu rõ hơn về LibAFL bạn có thể coi cái này [Fuzzers Like Lego @rC3](https://www.youtube.com/watch?v=3RWkT1Q5IV0)

### Prequesite

#### Rust installation: 

`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

#### AFL++ installation:

- Dependencies: 

```
sudo apt-get update
sudo apt-get install -y python3-pip cmake build-essential git gcc
sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
# try to install llvm 14 and install the distro default if that fails
sudo apt-get install -y lld-14 llvm-14 llvm-14-dev clang-14 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
sudo apt-get install -y ninja-build # for QEMU mode
```

- Build AFL++:

```
git clone https://github.com/AFLplusplus/AFLplusplus && cd AFLplusplus
export LLVM_CONFIG="llvm-config-15"
make distrib
sudo make install
```
Nếu như bạn gặp lỗi với unicornafl thì hãy thử downgrade version của python xuống 3.10.8.
```bash
curl https://pyenv.run | bash
pyenv install 3.10.8
pyenv global 3.10.8
```

- Test installation: 
```cmd=
cd ~
export PATH=$PATH :~/AFLplusplus
afl-fuzz -h
```

Result: 
```cmd=
gh0st@pl4y-Gr0und:~$ afl-fuzz -h
afl-fuzz++4.09a based on afl by Michal Zalewski and a large online community

afl-fuzz [ options ] -- /path/to/fuzzed_app [ ... ]

Required parameters:
  -i dir        - input directory with test cases (or '-' to resume, also see 
                  AFL_AUTORESUME)
  -o dir        - output directory for fuzzer findings

Execution control settings:
  -P strategy   - set fix mutation strategy: explore (focus on new coverage),
                  exploit (focus on triggering crashes). You can also set a
                  number of seconds after without any finds it switches to
                  exploit mode, and back on new coverage (default: 1000)
  -p schedule   - power schedules compute a seed's performance score:
                  fast(default), explore, exploit, seek, rare, mmopt, coe, lin
                  quad -- see docs/FAQ.md for more information
  -f file       - location read by the fuzzed program (default: stdin or @@)
  -t msec       - timeout for each run (auto-scaled, default 1000 ms). Add a '+'
                  to auto-calculate the timeout, the value being the maximum.
  -m megs       - memory limit for child process (0 MB, 0 = no limit [default])
  -O            - use binary-only instrumentation (FRIDA mode)
  -Q            - use binary-only instrumentation (QEMU mode)
  -U            - use unicorn-based instrumentation (Unicorn mode)
  -W            - use qemu-based instrumentation with Wine (Wine mode)
  -X            - use VM fuzzing (NYX mode - standalone mode)
  -Y            - use VM fuzzing (NYX mode - multiple instances mode)

Mutator settings:
  -a            - target input format, "text" or "binary" (default: generic)
  -g minlength  - set min length of generated fuzz input (default: 1)
  -G maxlength  - set max length of generated fuzz input (default: 1048576)
  -D            - enable deterministic fuzzing (once per queue entry)
  -L minutes    - use MOpt(imize) mode and set the time limit for entering the
                  pacemaker mode (minutes of no new finds). 0 = immediately,
                  -1 = immediately and together with normal mutation.
                  Note: this option is usually not very effective
  -c program    - enable CmpLog by specifying a binary compiled for it.
                  if using QEMU/FRIDA or the fuzzing target is compiled
                  for CmpLog then use '-c 0'. To disable Cmplog use '-c -'.
  -l cmplog_opts - CmpLog configuration values (e.g. "2ATR"):
                  1=small files, 2=larger files (default), 3=all files,
                  A=arithmetic solving, T=transformational solving,
                  X=extreme transform solving, R=random colorization bytes.

Fuzzing behavior settings:
  -Z            - sequential queue selection instead of weighted random
  -N            - do not unlink the fuzzing input file (for devices etc.)
  -n            - fuzz without instrumentation (non-instrumented mode)
  -x dict_file  - fuzzer dictionary (see README.md, specify up to 4 times)

Test settings:
  -s seed       - use a fixed seed for the RNG
  -V seconds    - fuzz for a specified time then terminate
  -E execs      - fuzz for an approx. no. of total executions then terminate
                  Note: not precise and can have several more executions.

Other stuff:
  -M/-S id      - distributed mode (-M sets -Z and disables trimming)
                  see docs/fuzzing_in_depth.md#c-using-multiple-cores
                  for effective recommendations for parallel fuzzing.
  -F path       - sync to a foreign fuzzer queue directory (requires -M, can
                  be specified up to 32 times)
  -T text       - text banner to show on the screen
  -I command    - execute this command/script when a new crash is found
  -C            - crash exploration mode (the peruvian rabbit thing)
  -b cpu_id     - bind the fuzzing process to the specified CPU core (0-...)
  -e ext        - file extension for the fuzz test input file (if needed)

To view also the supported environment variables of afl-fuzz please use "-hh".

Compiled with Python 3.11.4 module support, see docs/custom_mutators.md
Compiled without AFL_PERSISTENT_RECORD support.
Compiled with shmat support.
For additional help please consult docs/README.md :)

```
### Objective 

Ở chapter lần này tương ứng với exercise-2 trong [Fuzzing 101](https://github.com/antonio-morales/Fuzzing101/tree/main/Exercise%202). Mục đích của exercise này đó là chúng ta cần phải tìm một cái PoC/crash cho CVE-2009-3895 & CVE-2012-2836. 

[CVE-2009](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3895)

> Heap-based buffer overflow in the exif_entry_fix function (aka the tag fixup routine) in libexif/exif-entry.c in libexif 0.6.18 allows remote attackers to cause a denial of service or possibly execute arbitrary code via an invalid EXIF image. NOTE: some of these details are obtained from third party information.

[CVE-2012-2836](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2836)

> The exif_data_load_data function in exif-data.c in the EXIF Tag Parsing Library (aka libexif) before 0.6.21 allows remote attackers to cause a denial of service (out-of-bounds read) or possibly obtain sensitive information from process memory via crafted EXIF tags in an image.

### Before Fuzzing 

Trước khi bắt đầu fuzzing chúng ta cần phải chuẩn bị một số thứ 

#### Setup our target 

```!
gh0st@fuzzing-bible:~/fuzzing-101-solutions$ cargo new --lib exercise-2 
```

Chúng ta update member cho file Cargo.toml gốc 

> fuzzing-101-solutions/Cargo.toml
```
[workspace]

members = [
    "exercise-1",
    "exercise-2",
]
```

#### Install libexif 

```!
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$ wget https://github.com/libexif/libexif/archive/refs/tags/libexif-0_6_14-release.tar.gz
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$ tar -xvf libexif-0_6_14-release.tar.gz
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$ rm libexif-0_6_14-release.tar.gz
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$ mv libexif-libexif-0_6_14-release libexif
```

Install requirements 
```!
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$  sudo apt-get install autopoint libtool gettext libpopt-dev
```
#### Build our target 

Lần này mình tiếp tục sử dụng Makefile.toml vì sự tiện lợi của nó trong việc build những task mình cần cho fuzzing 

Nếu bạn chưa biết Makefile.toml là gì thì mình suggest bạn xem blog trước của mình, mình nói khá kỹ về tool này 
https://hackmd.io/jW6RBTbjTfqjGxRvR-DiLQ#Makefiletoml


```rust!=
[tasks.clean]
dependencies = ["cargo-clean", "libexif-clean", "build-clean"]

[tasks.cargo-clean]
command = "cargo"
args = ["clean"]

[tasks.libexif-clean]
command = "make"
args = ["-C", "libexif", "clean", "-i"]

[tasks.build-clean]
command = "rm"
args = ["-rf", "build/"]

[tasks.build]
dependencies = ["clean", "build-libexif"]
command = "cargo"
args = ["build"]


[tasks.build-libexif]
cwd = "libexif"
script = """
autoreconf -fi
./configure --enable-shared=no --prefix="${CARGO_MAKE_WORKING_DIRECTORY}/../build/"
make -i
make install -i
"""
```

Run the build 
```cmd!
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$ cargo make build 
```

Confirm build thành công 

```cmd
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$ ls build/lib/libexif.a
build/lib/libexif.a
```

### Get into fuzzing 


#### Setting up fuzzer 

> ~/fuzzing-101-solutions/exercise-2/Cargo.toml 

```rust!=
[dependencies]
libafl = {version = "0.10.1"}
libafl_cc = {version = "0.10.1"}
libafl_targets = {version = "0.10.1", features = [
    "libfuzzer",
    "sancov_pcguard_hitcounts",
    "sancov_cmplog",
]}
clap = "3.0.0-beta.5"
[lib]
name="exercisetwo"
crate-type=["staticlib]
```

#### Get some corpus 

```!
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$ mkdir corpus solutions
```

Ở trong [libexif repo](https://github.com/libexif/libexif) họ để sẵn một số file jpg để làm test data, để thuận tiện thì chúng ta sẽ lấy các file jpg đó về làm test case cho fuzzer. 

> fuzzing-101-solutions/exercise-2/corpus

```
git clone --no-checkout --filter=blob:none https://github.com/libexif/libexif.git
```

> fuzzing-101-solutions/exercise-2/corpus

```=
cd libexif
git checkout master -- test/testdata
```

> fuzzing-101-solutions/exercise-2/corpus/libexif

```=
mv test/testdata/*.jpg ../
cd ..
rm -rf libexif
```

Và đây là những file để làm test case cho fuzzer
>gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2/corpus

```ruby
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2/corpus$ ls -la
total 72
drwxrwxr-x 2 gh0st gh0st  4096 Thg 12 29 14:55 .
drwxrwxr-x 7 gh0st gh0st  4096 Thg 12 29 14:55 ..
-rw-rw-r-- 1 gh0st gh0st  2026 Thg 12 29 14:54 canon_makernote_variant_1.jpg
-rw-rw-r-- 1 gh0st gh0st  3978 Thg 12 29 14:54 fuji_makernote_variant_1.jpg
-rw-rw-r-- 1 gh0st gh0st  2850 Thg 12 29 14:54 olympus_makernote_variant_2.jpg
-rw-rw-r-- 1 gh0st gh0st  6140 Thg 12 29 14:54 olympus_makernote_variant_3.jpg
-rw-rw-r-- 1 gh0st gh0st 11458 Thg 12 29 14:54 olympus_makernote_variant_4.jpg
-rw-rw-r-- 1 gh0st gh0st  9604 Thg 12 29 14:54 olympus_makernote_variant_5.jpg
-rw-rw-r-- 1 gh0st gh0st  1346 Thg 12 29 14:54 pentax_makernote_variant_2.jpg
-rw-rw-r-- 1 gh0st gh0st  1918 Thg 12 29 14:54 pentax_makernote_variant_3.jpg
-rw-rw-r-- 1 gh0st gh0st  9132 Thg 12 29 14:54 pentax_makernote_variant_4.jpg
```

#### Executor 

Đối với mỗi loại fuzzer, về concept của việc thực thi các đoạn mã cần fuzz dưới mỗi lần test sẽ khác nhau với mỗi loại fuzzer, ví dụ như đối với hypervisor-based fuzzer như là [kAFL](https://github.com/IntelLabs/kAFL) thì mỗi test case nó sẽ chạy dưới các snapshot. Đối với libAFL fuzzer mỗi lần chạy test case nó sẽ gọi hàm "harness", có nghĩa là chúng ta gọi hàm cần fuzz trong file target với các tham số cụ thể dưới mỗi lần chạy fuzz. 


Đối với bài này thì chúng ta tiện hơn, vì trong test folder trong repo của [libexif](https://github.com/libexif/libexif/tree/master), họ đã viết 1 file harness cho chúng ta để test, [test-fuzzer-persistent.c](https://github.com/libexif/libexif/blob/master/test/test-fuzzer-persistent.c). 

Nôm na trong file test-fuzzer-persistent.c thì nó được viết dành cho afl fuzzer, vậy nên chúng ta có thể sử dụng trực tiếp nó luôn. 

```c
/**file test-fuzzer-persistent.c
 * from test-parse.c and test-mnote.c
 *
 * \brief Persistent AFL fuzzing binary (reaches 4 digits execs / second)
 *
 * Copyright (C) 2007 Hans Ulrich Niedermann <gp@n-dimensional.de>
 * Copyright 2002 Lutz Mueller <lutz@users.sourceforge.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA.
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "libexif/exif-data.h"
#include "libexif/exif-loader.h"
#include "libexif/exif-system.h"

__AFL_FUZZ_INIT();

#undef USE_LOG

#ifdef USE_LOG
static void
logfunc(ExifLog *log, ExifLogCode code, const char *domain, const char *format, va_list args, void *data)
{
	fprintf( stderr, "test-fuzzer: code=%d domain=%s ", code, domain);
	vfprintf (stderr, format, args);
	fprintf (stderr, "\n");
}
#endif

/** Callback function handling an ExifEntry. */
void content_foreach_func(ExifEntry *entry, void *callback_data);
void content_foreach_func(ExifEntry *entry, void *UNUSED(callback_data))
{
	char buf[2001];

	/* ensure \0 */
	buf[sizeof(buf)-1] = 0;
	buf[sizeof(buf)-2] = 0;
	exif_tag_get_name(entry->tag);
	exif_format_get_name(entry->format);
	exif_entry_get_value(entry, buf, sizeof(buf)-1);
	if (buf[sizeof(buf)-2] != 0) abort();
}


/** Callback function handling an ExifContent (corresponds 1:1 to an IFD). */
void data_foreach_func(ExifContent *content, void *callback_data);
void data_foreach_func(ExifContent *content, void *callback_data)
{
	printf("  Content %p: ifd=%d\n", (void *)content, exif_content_get_ifd(content));
	exif_content_foreach_entry(content, content_foreach_func, callback_data);
}
static int
test_exif_data (ExifData *d)
{
	unsigned int i, c;
	char v[1024];
	ExifMnoteData *md;

	fprintf (stdout, "Byte order: %s\n",
		exif_byte_order_get_name (exif_data_get_byte_order (d)));

	md = exif_data_get_mnote_data (d);
	if (!md) {
		fprintf (stderr, "Could not parse maker note!\n");
		return 1;
	}

	exif_mnote_data_ref (md);
	exif_mnote_data_unref (md);

	c = exif_mnote_data_count (md);
	for (i = 0; i < c; i++) {
		const char *name = exif_mnote_data_get_name (md, i);
		if (!name) continue;
		exif_mnote_data_get_name (md, i);
		exif_mnote_data_get_title (md, i);
		exif_mnote_data_get_description (md, i);
		exif_mnote_data_get_value (md, i, v, sizeof (v));
	}

	return 0;
}

/** Main program. */
int main(const int argc, const char *argv[])
{
	int		i;
	ExifData	*d;
	ExifLoader	*loader = exif_loader_new();
	unsigned int	xbuf_size;
	unsigned char	*xbuf;
	FILE		*f;
	struct		stat stbuf;
#ifdef USE_LOG
	ExifLog		*log = exif_log_new ();

	exif_log_set_func(log, logfunc, NULL);
#endif

#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
#endif

	unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
                                                 // and before __AFL_LOOP!

	while (__AFL_LOOP(10000)) {

		int len = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a call!

		d = exif_data_new_from_data(buf, len);

		/* try the exif loader */
	#ifdef USE_LOG
		exif_data_log (d, log);
	#endif
		exif_data_foreach_content(d, data_foreach_func, NULL);
		test_exif_data (d);

		xbuf = NULL;
		exif_data_save_data (d, &xbuf, &xbuf_size);
		free (xbuf);

		exif_data_set_byte_order(d, EXIF_BYTE_ORDER_INTEL);

		xbuf = NULL;
		exif_data_save_data (d, &xbuf, &xbuf_size);
		free (xbuf);

		exif_data_unref(d);

#if 0
		/* try the exif data writer ... different than the loader */

		exif_loader_write(loader, buf, len);

		d = exif_loader_get_data(loader);
		exif_data_foreach_content(d, data_foreach_func, NULL);
		test_exif_data (d);
		exif_loader_unref(loader);
		exif_data_unref(d);
#endif
	}
	return 0;
}
```


Tuy nhiên chúng ta cần sửa đổi một chút xíu để phù hợp với ngữ cảnh trong bài này. 

* Chúng ta cần phải sửa những lỗi liên quan tới các phiên bản khác nhau của libexif đang được sử dụng 
* Loại bỏ afl macros, các hàm in ra output như `exif_data_log`, `fprintf `, `printf`, `logfunc`. 
* Đổi tên hàm main thành `LLVMFuzzerTestOneInput`, mỗi lần chạy fuzz thì fuzzer sẽ gọi tới hàm callback [LLVMFuzzerTestOneInput](https://llvm.org/docs/LibFuzzer.html).
* Đối với hàm main thì mình sẽ để nó ở trong `ifdef, endif` vì chúng ta cần hàm main để đọc file corpus và gọi hàm LLVMFuzzerTestOneInput, hàm main sẽ được compile khi mà chúng ta đã chuẩn bị xong vì thế nên hàm main sẽ được đặt trong `ifdef`

`LLVMFuzzerTestOneInput.c`
```c
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "libexif/exif-data.h"
#include "libexif/exif-loader.h"
#define UNUSED(param) UNUSED_PARAM_##param __attribute__((unused))

// __AFL_FUZZ_INIT();
void content_foreach_func(ExifEntry *entry, void *callback_data);
void content_foreach_func(ExifEntry *entry, void *UNUSED(callback_data))
{
	char buf[2001];

	/* ensure \0 */
	buf[sizeof(buf)-1] = 0;
	buf[sizeof(buf)-2] = 0;
	exif_tag_get_name(entry->tag);
	exif_format_get_name(entry->format);
	exif_entry_get_value(entry, buf, sizeof(buf)-1);
	if (buf[sizeof(buf)-2] != 0) abort();
}
/** Callback function handling an ExifContent (corresponds 1:1 to an IFD). */
void data_foreach_func(ExifContent *content, void *callback_data);
void data_foreach_func(ExifContent *content, void *callback_data)
{
	printf("  Content %p: ifd=%d\n", (void *)content, exif_content_get_ifd(content));
	exif_content_foreach_entry(content, content_foreach_func, callback_data);
}

static int
test_exif_data (ExifData *d)
{
	unsigned int i, c;
	char v[1024];
	ExifMnoteData *md;

	fprintf (stdout, "Byte order: %s\n",
		exif_byte_order_get_name (exif_data_get_byte_order (d)));

	md = exif_data_get_mnote_data (d);
	if (!md) {
		fprintf (stderr, "Could not parse maker note!\n");
		return 1;
	}

	exif_mnote_data_ref (md);
	exif_mnote_data_unref (md);

	c = exif_mnote_data_count (md);
	for (i = 0; i < c; i++) {
		const char *name = exif_mnote_data_get_name (md, i);
		if (!name) continue;
		exif_mnote_data_get_name (md, i);
		exif_mnote_data_get_title (md, i);
		exif_mnote_data_get_description (md, i);
		exif_mnote_data_get_value (md, i, v, sizeof (v));
	}

	return 0;
}
// Main program. -> LLVMFuzzerTestOneInput 
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    int		i;
	ExifData	*d;
	ExifLoader	*loader = exif_loader_new();
	unsigned int	xbuf_size;
	unsigned char	*xbuf;
	FILE		*f;
	struct		stat stbuf;
    #ifdef USE_LOG
        ExifLog		*log = exif_log_new ();

        exif_log_set_func(log, logfunc, NULL);
    #endif
    d = exif_data_new_from_data(data, size);
    /* try the exif loader */
    #ifdef USE_LOG
		exif_data_log (d, log);
	#endif
    exif_data_foreach_content(d, data_foreach_func, NULL);
    test_exif_data (d);

    xbuf = NULL;
    exif_data_save_data (d, &xbuf, &xbuf_size);
    free (xbuf);

    exif_data_set_byte_order(d, EXIF_BYTE_ORDER_INTEL);

    xbuf = NULL;
    exif_data_save_data (d, &xbuf, &xbuf_size);
    free (xbuf);

    exif_data_unref(d);

    return 0;

}
#ifdef TRIAGE_TESTER
int main(int argc, char* argv[]){
    struct stat st;
    char *filename = argv[1];

    stat(filename,&st);
    FILE *fd = fopen(filename,"rb");
    char *buffer = (char*)malloc(sizeof(char)*(st.st_size));

    fread(buffer,sizeof(char),st.st_size,fd);
    LLVMFuzzerTestOneInput(buffer,st.st_size);

    free(buffer);
    fclose(fd);
}
#endif
```

#### Compiler 

Chúng ta cần một file để compile tất cả những gì chúng ta cần chạy fuzz. 

Ở trong file Cargo.toml chúng ta cần chỉnh lại một xíu, thêm vào `libafl_cc` và `libafl_target` ở trong dependency. 

```rust!
[dependencies]
libafl = {version = "0.10.1"}
libafl_cc = {version = "0.10.1"}
libafl_targets = {version = "0.10.1", features = [
    "libfuzzer",
    "sancov_pcguard_hitcounts",
    "sancov_cmplog",
]}
clap = "3.0.0-beta.5"

[lib]
name="exercisetwo"
crate-type=["staticlib"]
```

Tiếp theo đối với excercise-2_compiler.rs. Sau khi lướt một vòng trong repo của LibAFL thì mình nhận ra trong mỗi example của libafl họ đều dùng chung một template cho compiler. Ví dụ như bên dưới 
```rust!
// build.rs

use std::env;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();

    println!("cargo:rerun-if-changed=harness.c");

    // Enforce clang for its -fsanitize-coverage support.
    std::env::set_var("CC", "clang");
    std::env::set_var("CXX", "clang++");

    cc::Build::new()
        // Use sanitizer coverage to track the edges in the PUT
        .flag("-fsanitize-coverage=trace-pc-guard,trace-cmp")
        // Take advantage of LTO (needs lld-link set in your cargo config)
        //.flag("-flto=thin")
        .flag("-Wno-sign-compare")
        .file("./harness.c")
        .compile("harness");

    println!("cargo:rustc-link-search=native={}", &out_dir);

    println!("cargo:rerun-if-changed=build.rs");
}
```

Nên mình chỉ cần sửa đổi lại một xíu để phù hợp cho bài này hehe. 

`exercise-2_compiler.rs`

```rust!
use libafl_cc::{ClangWrapper, CompilerWrapper};
use std::env;

pub fn main() {
    let cwd = env::current_dir().unwrap();
    let args: Vec<String> = env::args().collect();

    let mut cc = ClangWrapper::new();

    if let Some(code) = cc
        .cpp(false)
        .silence(true)
        .parse_args(&args)
        .expect("Failed to parse the command line")
        .link_staticlib(&cwd, "exercisetwo")
        .add_arg("-fsanitize-coverage=trace-pc-guard")
        .add_arg("-fsanitize=address")
        .run()
        .expect("Failed to run the wrapped compiler")
    {
        std::process::exit(code);
    }
}
```

Ở đây mình thêm vào 
* -fsanitize-coverage=trace-pc-guard được thêm vào để track edge coverage, nó là [SanitizerCoverage ](https://clang.llvm.org/docs/SanitizerCoverage.html#introduction)
* -fsanitize=address đơn giản nó là [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) để detect các memory errors: Double free, UAF, OOB memory access. 

Ở trong exercise lần này target của chúng ta đó là cả 2 CVEs đều liên quan tới các lỗi của memory access (arbitrary read & write), tuy nhiên một số memory error sẽ không gây ra crash nhưng chúng vẫn có khả năng tác động nguy hiểm. Những lỗi như thế này thì ASAN sẽ là 1 sự lựa chọn phù hợp. 

Ở trong ngữ cảnh real-world stuff thì việc chạy ASAN sẽ cần tới ít nhất chạy 2 fuzzer, fuzz target với các config khác nhau và fuzz target với ASAN. Việc chạy ASAN sẽ khiến cho performance cost tăng lên, nó sẽ gây chậm quá trình chạy fuzz của chúng ta. 

#### Makefile.toml 

Trước mắt chúng ta cần có 1 file lib.rs để tránh bị lỗi trong quá trình build. 

`exercise-2/src/lib.rs`

```rust!
use libafl::Error;
use libafl_targets::libfuzzer_test_one_input;

#[no_mangle]
fn libafl_main() -> Result<(), Error> {
    libfuzzer_test_one_input(&[]);
    Ok(())
}
```

Mình sẽ chỉnh sửa nốt trong makefile.toml để hoàn thành mọi thứ.

`exercise-2/Makefile.toml`
```rust!
# tasks
[tasks.clean]
dependencies = ["cargo-clean","build-dir-clean","libexif-clean"]

[tasks.build]
dependencies = ["clean", "build-compilers", "copy-project-to-build", "build-libexif", "build-fuzzer"]

# clean up tasks
[tasks.cargo-clean]
command = "cargo"
args = ["clean"]

[tasks.libexif-clean]
command = "make"
args = ["-C", "libexif", "clean", "-i"]

[tasks.build-dir-clean]
command = "rm"
args = ["-rf", "build/"]

# task build
[tasks.build-compilers]
command = "cargo"
args = ["build", "--release"]

[tasks.copy-project-to-build]
script = """
mkdir -p build/
cp ${CARGO_MAKE_WORKING_DIRECTORY}/../target/release/ex2_compiler build/
cp ${CARGO_MAKE_WORKING_DIRECTORY}/../target/release/libexercisetwo.a build/
"""

[tasks.build-fuzzer]
cwd = "build"
command = "./ex2_compiler"
args = ["-I", "../libexif/libexif", "-I", "../libexif", "-o", "fuzzer", "../harness.c", "lib/libexif.a"]

[tasks.build-triager]
cwd = "build"
command = "./ex2_compiler"
args = ["-D", "TRIAGE_TESTER", "-I", "../libexif/libexif", "-I", "../libexif", "-o", "triager", "../harness.c", "lib/libexif.a"]

[tasks.build-libexif]
cwd = "libexif"
env = { "CC" = "${CARGO_MAKE_WORKING_DIRECTORY}/build/ex2_compiler", "LLVM_CONFIG" = "llvm-config-15"}
script = """
autoreconf -fi
./configure --enable-shared=no --prefix="${CARGO_MAKE_WORKING_DIRECTORY}/../build/"
make -i
make install -i
"""
```

Sau đó mình sẽ chạy `cargo make build` và kết quả sau khi chạy đó là file fuzzer trong `exercise-2/build`

![image](https://hackmd.io/_uploads/BJeS2PKCT.png)


![image](https://hackmd.io/_uploads/ByxU3vKRT.png)


### Writing Fuzzer 

Giống như exercise 1, mình sẽ sử dụng các component tương tự với bài trước nhưng sẽ phải có chỉnh sửa một xíu chứ không thể bên nguyên xi được. 


#### 1st Component: Corpus & Input 

Về phần này thì không có gì khác biệt với bài trước, mình vẫn sử dụng 
* OnDiskCorpus
* InMemoryCorpus 
* BytesInput 

Nếu như bạn chưa biết 3 cái trên là cái gì thì mình recommend xem lại bài post này [1st Component: Corpus & Input](https://y198nt.github.io/posts/fuzzing_holy_bible_chapter1/#1st-component-corpus--input), mình đã giải thích khá kỹ về 3 cái trên. 

```rust!
// path to input corpus
    let corpus_dirs = vec![PathBuf::from("./corpus")];

    // Corpus that will be evolved, we keep it in memory for performance
    let input_corpus = InMemoryCorpus::<BytesInput>::new();

    // Corpus in which we store solutions on disk so the user can get them after stopping the fuzzer
    let solutions_corpus = OnDiskCorpus::new(PathBuf::from("./solutions")).unwrap();
```

#### 2nd Component: Observer 

Mình cũng sẽ tái sử dụng lại các component của bài trước vì nó không có gì cần phải chỉnh sửa hoặc thay đổi.

* StdMapObserver: Vì lần này mình sẽ sử dụng InMemoryExecutor(mình sẽ nói ở bên dưới) nên việc sử dụng StdMapObserver là cần thiết cho việc lấy lại trạng thái của coverage map. Chúng ta không thể sử dụng ConstMapObserver vì Max Edges Map không thể xác định được trong quá trình compile. 
* HitcountsMapObserver để tăng thêm edge coverage đạt được từ StdMapObserver. Để xác định đoạn mã nào có lỗi trong flow của mình.
* TimeObserver, cung cấp thông tin về thời gian trong quá trình chạy fuzz của testcase hiện tại, hỗ trợ cho các component tiếp theo.

Xem lại bài trước của mình [2nd Component: Observer](https://y198nt.github.io/posts/fuzzing_holy_bible_chapter1/#2nd-component-observer) để hiểu rõ hơn về HitcountsMapObserver và TimeObserver. 

```rust!
    let edges_observer = HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") });

    // Create an observation channel to keep track of the execution time and previous runtime
    let time_observer = TimeObserver::new("time");
```

#### 3rd Component: Feedback 

* MaxMapFeedback xác định xem liệu coverage map hiện tại có lớn hơn so với coverage map mà chúng ta đưa vào từ đầu rồi từ đó xác định test case hiện tại có phù hợp để đưa vào input tiếp theo hay không. 
* TimeFeedback theo dõi thời gian của quá trình thực thi test case hiện tại, và xác định xem thời gian hiện tại có "interesting" hay không để đưa test case hiện tại làm input tiếp theo. 

Mình nói rõ hơn trong bài trước [3nd Component: Feedback](https://y198nt.github.io/posts/fuzzing_holy_bible_chapter1/#3rd-component-feedback)

```rust!
    let mut feedback = feedback_or!(
        // New maximization map feedback (attempts to maximize the map contents) linked to the
        // edges observer and the feedback state. This one will track indexes, but will not track
        // novelties, i.e. tracking(... true, false).
        MaxMapFeedback::tracking(&edges_observer, true, false),
        // Time feedback, this one does not need a feedback state, nor does it ever return true for
        // is_interesting, However, it does keep track of testcase execution time by way of its
        // TimeObserver
        TimeFeedback::with_observer(&time_observer)
    );
let mut objective =
        feedback_and_fast!(CrashFeedback::new(),
            MaxMapFeedback::new(&edges_observer));
```

Việc mình sử dụng CrashFeedback ở đây đó là fuzzer sẽ xác định nếu input của test case hiện tại gây crash thì nó sẽ là "interesting" input và sẽ được đưa vào làm corpus cho input tiếp theo sau khi đã mutated. 

#### 4th Component: State 

* StdState nó sẽ lấy trạng thái hiện tại của fuzzer và nó là cái mà mình thấy sử dụng được trong bài lần này. 

```rust!
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // random number generator with a time-based seed
            StdRand::with_seed(current_nanos()),
            input_corpus,
            solutions_corpus,
            // States of the feedbacks that store the data related to the feedbacks that should be
            // persisted in the State.
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });
```

#### 5th Component: Monitor 

Tương tự với post trước, mình sẽ sử dụng `SimpleMonitor` và component này chỉ in ra terminal các thông tin cần thiết cho chúng ta. 

```rust!
    let monitor = MultiMonitor::new(|s| {
        println!("{}", s);
    });
```

#### 6th Component: EventManager 

Bài lần trước mình đã sử dụng SimpleEventManager nhưng lần này mình sẽ sử dụng [LlmpRestartingEventManager](https://docs.rs/libafl/0.10.1/libafl/events/llmp/struct.LlmpRestartingEventManager.html) để tăng performance cho fuzzer. Nó hoạt động dựa trên SimpleEventManager nhưng với mỗi child process bị crash LlmpRestartingEventManager sẽ fork ra một process mới để tiếp tục quá trình fuzzing 

```rust!
    let (state, mut mgr) = match setup_restarting_mgr_std(monitor, 1337, EventConfig::AlwaysUnique)
    {
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarting manager: {}", err);
            }
        },
    };
```

#### 7th Component: Scheduler 

Về Scheduler mình sẽ sử dụng lại các component của bài trước
* QueueScheduler sử dụng để sắp xếp các corpus theo 1 thứ tự nhất định 
* IndexesLenTimeMinimizerScheduler sẽ ưu tiên các test case gọn và nhanh ở trong corpus input

```rust!
let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());
```

#### 8th Component: Fuzzer 

`StdFuzzer` sẽ kết hợp các component với nhau và chạy chúng.  Để hiểu rõ hơn thì hãy đọc lại bài post trước của mình [8th Component: Fuzzer](https://y198nt.github.io/posts/fuzzing_holy_bible_chapter1/#8th-component-fuzzer)

```rust!
// A fuzzer with feedback, objectives, and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
```

#### 9th Component: Harness 

Về exercise lần này mình sẽ thêm vào component harness, nó sẽ có tác dụng đưa vào các bytes đã được mutate bởi fuzzer và đưa chúng vào trong hàm LLVMFuzzerTestOneInput trong file harness.c

```rust!
    //
    // Component: harness
    //

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buffer = target.as_slice();
        libfuzzer_test_one_input(buffer);
        ExitKind::Ok
    };
```

#### 10th Component: Executor 

Component này mình thêm vào với hàm tương ứng là 
* [InProcessExecutor](https://docs.rs/libafl/0.10.1/libafl/executors/inprocess/type.InProcessExecutor.html) sẽ thay thế ForkserverExecutor là bởi vì chúng ta chạy fuzz dưới dạng một file binary được chạy độc lập, việc này sẽ làm tăng tốc độ quá trình fuzzing. 
* [TimeoutExecutor](https://docs.rs/libafl/0.10.1/libafl/executors/timeout/struct.TimeoutExecutor.html) set timeout trước khi mỗi lần chạy file target tránh việc các test case gây chậm quá trình fuzzing, ngoài ra nó còn kết hợp với các component khác để xác định các test case gây time out. 

```rust!
 let in_proc_executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .unwrap();

    let timeout = Duration::from_millis(5000);

    // wrap in process executor with a timeout
    let mut executor = TimeoutExecutor::new(in_proc_executor, timeout);
```

#### 11th Component: Mutator & Stage 

* StdScheduledMutator
* StdMutationalStage

```rust=
    //
    // Component: Mutator
    //

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());

    //
    // Component: Stage
    //

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
```

#### Combine Everythin and Running the fuzzer 

```rust!
fuzzer
        .fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 1000)
        .unwrap();
```

### Fuzz'em All 

#### Setup
Sau khi mọi thứ đã hoàn tất và việc bây giờ của chúng ta đó là build và chạy fuzz 

![image](https://hackmd.io/_uploads/Hy34gtFRa.png)


Sau khi build xong thì kết quả là chúng ta sẽ có 1 folder build như bên dưới 

![image](https://hackmd.io/_uploads/HJBDlYYAa.png)

Và việc bây giờ của chúng ta đó là setup ASAN và chạy fuzz. 

Như mình đã nói ở trên thì để đạt được target mà chúng ta cần đó là memory error thì chúng ta cần phải có ASAN, tuy nhiên ở chế độ mặc định thì ASAN sẽ tự động exit sau mỗi lần dính crash, nhưng target của chúng ta cần đó là 2 bug, OOB read and write, và việc exit của ASAN sẽ khiến cho quá trình fuzzing của chúng ta bị chững lại và khiến cho chúng ta phải chạy lại từ đầu. Thế nên command line bên dưới sẽ set flag cho ASAN không exit khi mỗi lần gặp crash. 

`ASAN_OPTIONS=abort_on_error=1`


#### Chạy fuzzing 

Để chạy fuzzer chúng ta cần 2 terminal, 1 cái để fuzz target với config mà chúng ta đã xác định từ trước và 1 cái để fuzz target với ASAN 

`Terminal 1 running fuzzer with ASAN`

![image](https://hackmd.io/_uploads/ByIeGFKRp.png)

`Terminal 2 running fuzzer target`

![image](https://hackmd.io/_uploads/SJ_7MFK0T.png)


#### Result 

Và sau khi chạy 1 lúc thì chúng ta đã có kết quả 

![image](https://hackmd.io/_uploads/BkUDfFKCT.png)


![image](https://hackmd.io/_uploads/HJChMttAT.png)

Ví dụ về report của ASAN 

![image](https://hackmd.io/_uploads/rJyJ7YKC6.png)


Còn 1 đoạn về triage nữa nhưng mình khá lười để viết, nôm na nó dùng để xác định xem các solution của chúng ta có unique bug nào hay không, nhưng bài tới đây cũng khá dài rồi, hẹn các bạn vào 1 bài khác mình sẽ làm rõ về phần này (hoặc không ....)

<iframe src="https://giphy.com/embed/Z5xk7fGO5FjjTElnpT" width="480" height="480" frameBorder="0" class="giphy-embed" allowFullScreen></iframe><p><a href="https://giphy.com/gifs/moodman-dog-confused-rigley-beans-Z5xk7fGO5FjjTElnpT">via GIPHY</a></p>










