include Makefile.config

SUBDIRS=key_extractor stub

all: subdirs

clean: subdirs

subdirs:
	for subdir in $(SUBDIRS); do \
	    echo "Entering $$subdir"; \
	    make -C $$subdir $(MAKECMDGOALS); \
	done

