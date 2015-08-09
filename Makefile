
OUTPUT		?= /usr/local

ARCH		?=x86
CROSS_PREFIX	?=

ifeq ($(ARCH), pi)
	CROSS_PREFIX=arm-linux-gnueabihf-
endif

CC	= ${CROSS_PREFIX}gcc
CXX	= ${CROSS_PREFIX}g++
LD	= ${CROSS_PREFIX}ld
AR	= ${CROSS_PREFIX}ar

COLOR	= 1
CC_V	= $(CC_$(COLOR))
CXX_V	= $(CXX_$(COLOR))
LD_V	= $(LD_$(COLOR))
AR_V	= $(AR_$(COLOR))
CP_V	= $(CP_$(COLOR))
RM_V	= $(RM_$(COLOR))
CYAN	= "\033[36m"
GREEN	= "\033[1;32m"
NC	= "\033[0m"
AA	= "\033[33m"
CC_0	= $(CC)
CC_1	= @printf '\t%b\t%b\n' $(CYAN)CC$(NC) $(CYAN)$@$(NC); $(CC)
CXX_0	= $(CXX)
CXX_1	= @printf '\t%b\t%b\n' $(CYAN)CXX$(NC) $(CYAN)$@$(NC); $(CXX)
LD_0	= $(LD)
LD_1	= @printf '\t%b\t%b\n' $(GREEN)LD$(NC) $(GREEN)$@$(NC); $(LD)
AR_0	= $(AR)
AR_1	= @printf '\t%b\t%b\n' $(AA)AR$(NC) $(AA)$@$(NC); $(AR)
CP_0	= cp
CP_1	= @printf '\t%b\n' $(AA)install$(NC); cp
RM_0	= rm
RM_1	= @printf '\t%b\n' $(AA)clean$(NC); rm

########
TGT_APP 	= rpcd
OBJS_APP    	= ${TGT_APP}.o
OBJS_APP   	+= engine.o ext/rpcd_common.o

CFLAGS	:= -g -Wall -fPIC
CFLAGS	+= -Werror
CFLAGS	+= -I./
LDFLAGS	:= -lpthread
LDFLAGS	+= -llog
LDFLAGS	+= -lgevent
LDFLAGS	+= -lskt
LDFLAGS	+= -ldict
LDFLAGS	+= -lworkq
LDFLAGS	+= -lrpc

.PHONY : all clean

TGT	:= $(TGT_APP)

OBJS	:= $(OBJS_APP)

all: $(TGT)

%.o:%.c
	$(CC_V) -c $(CFLAGS) $< -o $@

$(TGT_APP): $(OBJS)
	$(CC_V) -o $@ $^ $(LDFLAGS)

install:
	$(CP_V) -f $(TGT_APP) ${OUTPUT}/bin
clean:
	$(RM_V) -f $(OBJS)
	$(RM_V) -f $(TGT)

uninstall:
	$(RM_V) -f ${OUTPUT}/bin/$(TGT_APP)
