# destrier-harness image. Builds FROM the standard attacker toolbox (harness-base)
# and bakes the full pwn/web toolchain, since the run cell is sealed (no runtime
# fetch). The platform's `boxr agent build` overrides BASE with its registry copy
# and rewrites runtime.image in harness.yaml with the pushed digest.
#
# `boxr agent build` authenticates with your API key and pulls this managed base
# (registry.destrier.io grants pull to every signed-in author). For a plain
# `docker build`, pass a base you can pull, e.g. --build-arg BASE=harness-base:local.
ARG BASE=registry.destrier.io/destrier-harness/base:0.5.0
FROM ${BASE}

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PYTHONUNBUFFERED=1

# System tooling the base does not already carry: web wordlists (seclists), a
# headless browser, the pwn/rev debug stack, a C toolchain (build-essential is
# needed to compile exploits and the seccomp-tools native gem), Ruby, AND the
# 32-bit (i386) toolchain — a headline pwn class ships 32-bit binaries, so
# gcc-multilib + the i386 libc/debug libc must be present to build, debug and
# leak against them. i386 is enabled first so the :i386 debug libc resolves.
# binwalk + squashfs-tools + e2fsprogs + p7zip-full + radare2 give the firmware
# reverse-engineering path its extract/analyze tools. e2fsprogs' debugfs and 7z
# extract ext4/other images WITHOUT root or a loop device (a sealed cell is
# unprivileged, so `mount -o loop` is unavailable). See the firmware-re skill.
# qemu-user-static runs foreign-arch (MIPS/ARM) firmware binaries the x86 cell cannot
# execute natively — the RE path for a router/camera service binary carved from firmware.
RUN dpkg --add-architecture i386 && apt-get update && apt-get install -y --no-install-recommends \
      seclists \
      chromium \
      gdb gdbserver ltrace strace \
      ruby ruby-dev \
      patchelf elfutils file binutils \
      binwalk squashfs-tools e2fsprogs p7zip-full radare2 liblzo2-dev \
      qemu-user-static \
      build-essential libseccomp-dev ninja-build meson \
      gcc-multilib \
      libc6-dbg \
      libc6-i386 libc6-dbg:i386 \
      proxychains4 \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf "$(command -v proxychains4)" /usr/local/bin/proxychains

# Python exploitation stack (pwntools drives python_exec). PySocks lets http_request
# route through a pivot's SOCKS proxy to reach an inner host.
# unicorn+capstone emulate/disassemble a single parser function to recover a custom
# protocol frame when the binary won't run standalone or the parser is obfuscated
# (opaque predicates) — the intended shortcut for that class (see protocol-reversing).
RUN pip install --no-cache-dir \
      pwntools \
      ROPgadget \
      ropper \
      requests \
      PySocks \
      unicorn \
      capstone

# r2dec: a lightweight (duktape/JS) radare2 decompiler plugin — pseudo-C for an opaque
# parser, far more legible than raw disasm, and NOT Ghidra (no heavy native build). Baked
# at build time via r2pm (the run cell is sealed). Gives `pdd`/`pdda` inside radare2.
# Non-fatal: the apt radare2 ships no r_core dev lib, so r2dec cannot link here.
# radare2's built-in `pdc` covers pseudo-decompilation; this auto-installs r2dec
# only if a future source-built radare2 provides the dev libs.
RUN r2pm -U && r2pm -ci r2dec || true

# Firmware RE: python filesystem extractors for the layouts binwalk carves beyond
# squashfs (JFFS2 via jefferson, UBIFS via ubi_reader). Sealed cell => baked, not
# fetched; the firmware-re skill assumes them alongside binwalk/radare2/unsquashfs.
# ubi_reader pulls python-lzo (native), so liblzo2-dev is in the apt block above:
# real vendor firmware (e.g. Milesight) ships the rootfs as a UBI/UBIFS-LZO volume
# that binwalk+squashfs alone miss — ubireader_extract_files carves it.
# --ignore-installed: the kali base ships cryptography via apt (no RECORD file), so
# pip cannot uninstall it to satisfy ubi_reader's cryptography>=50 pin; install fresh.
RUN pip install --no-cache-dir --ignore-installed \
      jefferson \
      ubi_reader

# Ruby pwn helpers.
RUN gem install --no-document one_gadget seccomp-tools

# gef: a single-file gdb enhancement (heap/rop views), sourced offline at runtime.
RUN wget -q -O /opt/gef.py https://raw.githubusercontent.com/hugsy/gef/main/gef.py \
    && printf 'source /opt/gef.py\n' > /root/.gdbinit

# linpeas + pspy: single-file privilege-escalation enumerators, baked because the
# run cell is sealed (no runtime fetch) and neither is in kali-linux-headless.
# This makes the skills' "baked-in linpeas" promise true and unlocks the
# process/cron-watch privesc class (pspy needs no root to see root's timed jobs).
RUN wget -q -O /usr/local/bin/linpeas.sh https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh \
    && wget -q -O /usr/local/bin/pspy64 https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 \
    && wget -q -O /usr/local/bin/pspy32 https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32 \
    && chmod +x /usr/local/bin/linpeas.sh /usr/local/bin/pspy64 /usr/local/bin/pspy32 \
    && ln -sf /usr/local/bin/pspy64 /usr/local/bin/pspy

# chisel: a single static Go binary for TCP/SOCKS tunneling — the multi-host pivot
# path in a sealed cell (no runtime fetch). Baked and promised so the pivoting skill
# can reach an inner host through a foothold.
RUN wget -q -O /tmp/chisel.gz https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz \
    && gunzip -c /tmp/chisel.gz > /usr/local/bin/chisel \
    && chmod +x /usr/local/bin/chisel \
    && rm -f /tmp/chisel.gz

# libc-database scripts, with BOTH the 64-bit and 32-bit system libc pre-indexed
# for offline id/leak work. Broader libc sets can be added at build time if a
# competition needs them.
RUN git clone --depth 1 https://github.com/niklasb/libc-database /opt/libc-database \
    && ( cd /opt/libc-database && ./add /lib/x86_64-linux-gnu/libc.so.6 2>/dev/null || true ) \
    && ( cd /opt/libc-database && ./add /lib/i386-linux-gnu/libc.so.6 2>/dev/null || true )

# Offline CVE corpus: a small curated set of advisory-level leads (id, product,
# class/CWE, component, one-line mechanism, technique skill) the model greps by
# fingerprint. No PoCs/params/creds are baked — it points at the right technique
# skill, the model derives the exploit. Baked because the run cell has no internet.
COPY cve-corpus/ /opt/cve-corpus/

# The harness itself. Code on PYTHONPATH at /app; the attacker works in /workspace.
ENV PYTHONPATH=/app
COPY harness/ /app/harness/
COPY skills/ /app/skills/
COPY config.yaml /app/config.yaml

WORKDIR /workspace
ENTRYPOINT ["/destrier/init"]
CMD ["python3", "-m", "harness"]
