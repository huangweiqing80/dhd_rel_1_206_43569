#
#!/bin/sh
#  

FIXFILES="swchangelog.commit"
ADDFILES=""

MODFILES=""

DELFILES=""

COMMIT_REASON="logW1: Change makefile to make tools compiling successfully"

if [ "-${ADDFILES}" = "-" ]; then
echo "Do not need add any files"
else
echo "Add ${ADDFILES} to repository"
git add -f ${ADDFILES}
fi

echo "Added files: ${ADDFILES}; Modified files: ${MODFILES}; Deleted files: ${DELFILES}"
git commit -m "${COMMIT_REASON}" ${FIXFILES} ${ADDFILES} ${MODFILES} ${DELFILES}