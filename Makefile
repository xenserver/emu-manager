TARGET = emu-manager

OBJS :=	emum.o \
	em-client.o 

CFLAGS  = -I$(shell pwd)

ifeq ($(D), 1)
CFLAGS += -g
else
CFLAGS += -g -O1
endif

# _GNU_SOURCE for asprintf.
CFLAGS += -Wall -Werror

LDLIBS := -ljson-c


# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,$(@D)/.$(@F).d

DEPS     = .*.d

LDFLAGS += -g 

all: $(TARGET)

$(TARGET): $(LIBS) $(OBJS)
	gcc -o $@ $(LDFLAGS) $(OBJS) $(LIBS) $(LDLIBS)

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
