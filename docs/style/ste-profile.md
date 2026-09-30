# The zig-sdk profile of ASD-STE100

This page tells you how this project applies ASD-STE100 Simplified Technical English, Issue 9. The standard is copyrighted. This page cites its rules by number and does not copy its text.

## Surfaces

The profile applies to these texts:

- The README and the other Markdown files in the repository.
- Every page of the wiki.
- Doc comments (`///` and `//!`) in Zig source files.
- User-visible messages in the SDK.

The profile does not apply to identifiers, commit messages, quoted specification text, licenses, fixtures, and generated files.

## Rules that the linter checks

`zig build lint-docs` reports an error for these rules:

- STE-5.1: a procedural sentence has 20 words or less.
- STE-6.3: a descriptive sentence has 25 words or less.
- STE-6.6: a paragraph has six sentences or less.
- STE-8.1: no semicolons.
- STE-4.2: no contractions.
- STE-1.1: only approved words. The project word list in `docs/dictionary/project_word_list.txt` names words that we do not use.
- STE-GR-6: no Latin abbreviations.
- STE-GR-7: no gendered pronouns.

The linter reports a warning for these rules:

- STE-3.4: no complex verb forms.
- STE-3.5: an `-ing` word is only a technical noun from `docs/dictionary/ing_allowlist.txt`.
- STE-3.6: active voice.
- PRJ-1: a sentence starts with an uppercase letter.

## Word count

The linter counts words as the standard tells in rules 8.5 to 8.7. Text in parentheses, numbers, hyphenated words, and code spans count as one word.

## Procedural and descriptive text

A section with a heading that starts with "Steps", "Procedure" or "How to" is procedural. Items of a numbered list are procedural. All other text is descriptive.

## RFC 2119 words

The MCP specification uses the words of RFC 2119. In our prose we write them like this:

| Specification word | Our prose |
| --- | --- |
| MUST | must |
| MUST NOT | must not |
| SHOULD | We recommend that ... |
| MAY | can |

Use the uppercase words only inside a quotation of the specification.

## Technical nouns and technical verbs

The project declares its technical nouns in `docs/dictionary/technical_nouns.txt` and its technical verbs in `docs/dictionary/technical_verbs.txt`. Use one term for one concept. Do not use a technical noun as a verb.
