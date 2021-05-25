include ../Makefile.config

#SDK_PATH?=/opt/android-sdk
#PROTOBUF_JAR?=protobuf.jar
#PROTOC?=protoc
#JAVAC?=javac

SOURCES=$(wildcard *.java)

CLASSES=$(SOURCES:.java=.class)
DEX=classes.dex


DX=$(shell find $(SDK_PATH)/build-tools/ -name dx -path "*28.*" -print -quit)


JAVAFLAGS=-target 1.8 -source 1.8 \
	-bootclasspath $(SDK_PATH)/platforms/android-28/android.jar \
	-classpath .:$(PROTOBUF_JAR) -Xlint -g


all: axolotl_proto dex

clean: axolotl_proto_clean dex_clean
	rm -f *.class


axolotl_proto: axolotl.proto
	$(PROTOC) --java_out=. axolotl.proto

axolotl_proto_clean:
	rm -f Axolotl.java SignedPreKey.java SignedPreKeyOrBuilder.java


dex: axolotl.proto $(CLASSES)
	$(DX) --dex --output=$(DEX) *.class $(PROTOBUF_JAR)

dex_clean:
	rm -f $(DEX)


%.class: %.java
	$(JAVAC) $(JAVAFLAGS) $<

