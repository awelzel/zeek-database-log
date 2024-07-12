# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -r $TRACES/test.pcap $PACKAGE %INPUT
#
# @TEST-EXEC: btest-diff database.log
