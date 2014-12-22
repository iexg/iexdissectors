packet-iexdissectors.h: packet-iexdissectors.h.in

plugindir = $(DISSECTOR_DIR)

plugin_LTLIBRARIES = \
        iexdissectors.la


iexdissectors_la_CFLAGS = \
        -fPIC \
        $(WIRESHARK_CFLAGS) \
        $(GLIB_CFLAGS)

iexdissectors_la_LIBS = \
        $(WIRESHARK_LIBS) \
        $(GLIB_LIBS)

iexdissectors_la_LDFLAGS = \
        -module \
        -avoid-version

iexdissectors_la_SOURCES = \
	plugin.c \
        packet-iextp.c \
        packet-iextops.c
