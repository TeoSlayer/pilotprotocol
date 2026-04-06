# IETF Internet-Draft Build Tooling
# Converts kramdown-rfc Markdown to RFCXML, then to TXT and HTML
#
# Prerequisites:
#   brew install ruby
#   /opt/homebrew/opt/ruby/bin/gem install kramdown-rfc
#   pip3 install xml2rfc

DRAFTS = draft-teodor-pilot-problem-statement-01 \
         draft-teodor-pilot-protocol-01

XML  = $(addsuffix .xml, $(DRAFTS))
TXT  = $(addsuffix .txt, $(DRAFTS))
HTML = $(addsuffix .html, $(DRAFTS))

# Tool paths (auto-detect or fallback to Homebrew Ruby)
KRAMDOWN = $(shell which kramdown-rfc2629 2>/dev/null || echo /opt/homebrew/lib/ruby/gems/4.0.0/bin/kramdown-rfc2629)
XML2RFC  = xml2rfc

.PHONY: all build install lint clean

all: build

# Keep XML intermediates (Make auto-deletes implicit intermediates)
.PRECIOUS: %.xml

build: $(XML) $(TXT) $(HTML)

# Markdown -> RFCXML via kramdown-rfc (warnings to stderr, XML to stdout)
%.xml: %.md
	$(KRAMDOWN) $< 2>/dev/null >$@

# RFCXML -> Plain text
%.txt: %.xml
	$(XML2RFC) --text $<

# RFCXML -> HTML
%.html: %.xml
	$(XML2RFC) --html $<

install:
	brew install ruby
	/opt/homebrew/opt/ruby/bin/gem install kramdown-rfc
	pip3 install xml2rfc

lint: $(TXT)
	@for f in $(TXT); do \
		echo "=== idnits $$f ==="; \
		idnits --verbose $$f || true; \
		echo; \
	done

clean:
	rm -f $(XML) $(TXT) $(HTML)
