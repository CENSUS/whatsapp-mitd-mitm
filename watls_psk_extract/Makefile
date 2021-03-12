#
# Set "SDK_DIR" and "JAVA_HOME" below.
#
# If you have multiple Android devices connected on your PC, set "ANDROID_SERIAL"
# before running "make deploy".
#

SOURCES=WatlsPskExtract.java ReflectionAPI.java

CLASSES=$(patsubst %.java, %.class, $(SOURCES))

# SDK_DIR=~/Library/Android/sdk
# SDK_DIR=/opt/android-sdk
ANDROID_JAR=$(shell find $(SDK_DIR) -type f -name android.jar | tail -n 1)
DX=$(shell find $(SDK_DIR) -type f -name dx | tail -n 1)

JAVA_VERSION=1.8
JAVAFLAGS=-target $(JAVA_VERSION) -source $(JAVA_VERSION) -bootclasspath $(ANDROID_JAR) -Xlint -g
JAVAC=$(JAVA_HOME)/bin/javac

DEX=classes.dex

$(DEX): $(CLASSES)
	$(DX) --dex --output="$@" $(CLASSES)

%.class: %.java
	$(JAVAC) $(JAVAFLAGS) $<

clean:
	rm -f $(DEX) $(CLASSES)

deploy:
	adb shell mkdir -p /data/local/tmp/watls_psk_extract
	adb push classes.dex run.sh /data/local/tmp/watls_psk_extract
	adb shell chmod +x /data/local/tmp/watls_psk_extract/run.sh

