BUILDDIR=${1:-/tmp/build}
#if [ ! -d wolfssl ]; then
#    git clone https://github.com/wolfSSL/wolfssl wolfssl
#fi
python3 secrets_to_c_header.py /secrets/global.secrets ${HSM_PIN} ${PERMISSIONS}
make BUILDDIR=${BUILDDIR}
cp ${BUILDDIR}/hsm.elf ${BUILDDIR}/hsm.bin /out
