# Build paper.pdf.
#
# The `[?]` placeholders that appear instead of citation numbers mean the
# bibliography was never processed: LaTeX alone cannot resolve \cite keys.
# BibTeX must run between LaTeX passes, and LaTeX must then run twice more
# for the numbers and cross-references to settle. `make` does all four.

PAPER := paper

.PHONY: all clean check

all: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex references.bib
	pdflatex -interaction=nonstopmode -halt-on-error $(PAPER).tex
	bibtex $(PAPER)
	pdflatex -interaction=nonstopmode -halt-on-error $(PAPER).tex
	pdflatex -interaction=nonstopmode -halt-on-error $(PAPER).tex
	@echo
	@echo "--- unresolved references (should be empty) ---"
	@grep -c "Citation.*undefined" $(PAPER).log && echo "UNDEFINED CITATIONS -- see $(PAPER).blg" || echo "citations OK"
	@grep -c "Reference.*undefined" $(PAPER).log && echo "UNDEFINED REFS" || echo "refs OK"
	@grep -n "Overfull \\\\hbox" $(PAPER).log | head -20 || true

# Report BibTeX problems without a full rebuild.
check:
	@bibtex $(PAPER) 2>&1 | grep -Ei "error|warning|repeated" || echo "bibtex clean"

clean:
	rm -f $(PAPER).aux $(PAPER).bbl $(PAPER).blg $(PAPER).log \
	      $(PAPER).out $(PAPER).toc $(PAPER).pdf
