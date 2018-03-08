TARGET = emu-manager

OBJS := \
	emum.o \
	em-client.o \
	lib.o \
	qmp.o

CFLAGS  = -I$(shell pwd) $$(pkg-config --cflags json-c)

ifeq ($(D), 1)
CFLAGS += -g -O0 -DDEBUG_LOGGING
else
CFLAGS += -g -O2
endif

CFLAGS += -D_GNU_SOURCE \
          -Wall \
          -Werror \
          -Wextra \
          -Wstrict-prototypes \
          -Wold-style-declaration \
          -Wmissing-prototypes

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,$(@D)/.$(@F).d

DEPS     = .*.d

LDFLAGS += -g $$(pkg-config --libs json-c) -lempserver

all: $(TARGET)

$(TARGET): $(OBJS)
	gcc -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	gcc -o $@ $(CFLAGS) -c $<

.PHONY: ALWAYS

clean:
	rm -f $(OBJS)
	rm -f $(DEPS)
	rm -f $(TARGET)
	rm -f TAGS

.PHONY: TAGS
TAGS:
	find . -name \*.[ch] | etags -

-include $(DEPS)

print-%:
	echo $($*)
