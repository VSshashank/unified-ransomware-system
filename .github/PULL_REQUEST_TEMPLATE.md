<!--
Section 4.4.2 of the project documentation requires every PR to carry a
Description, Testing done, and Screenshots. The three headings below are those
three; leave them all in place even when a section is short.
-->

## Description

<!-- What changed and why. Link the requirement it satisfies where there is one
     (a Table 4.x deliverable, a Table 5.8 test case, a Table 5.9 benchmark). -->

## Testing done

<!-- Commands run and their real output. Numbers here must come from a command
     that was actually executed - a benchmark quoted from a previous run is not
     testing done.

     Baseline for the full suite:

       for svc in gateway ledger monitor ml-engine response; do \
         (cd services/$svc && python -m pytest -q); done
-->

- [ ] Full test suite run, no regression against the recorded baseline
- [ ] New behaviour has a test that fails without the change
- [ ] False-positive rate still 0/40 (detection changes only)
- [ ] Table 5.9 benchmarks still met (performance-sensitive changes only)

## Screenshots

<!-- Dashboard, terminal output, or a report artefact. "N/A - no user-visible
     change" is a valid answer; deleting the heading is not. -->

---

## Review checklist (§4.4.2)

- [ ] At least one approval before merge
- [ ] CI pipeline passes (tests, linting)
- [ ] Reviewed within 24 hours of opening
