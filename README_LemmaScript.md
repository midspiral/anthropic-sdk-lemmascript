# anthropic-sdk-typescript — Verified with LemmaScript

[![LemmaScript verified](https://img.shields.io/github/actions/workflow/status/midspiral/anthropic-sdk-lemmascript/lemmascript.yml?branch=lemmascript&label=LemmaScript%20verified)](https://github.com/midspiral/anthropic-sdk-lemmascript/actions/workflows/lemmascript.yml)

Fork of [anthropics/anthropic-sdk-typescript](https://github.com/anthropics/anthropic-sdk-typescript) with the path-containment predicate behind [CVE-2026-34451](https://advisories.gitlab.com/pkg/npm/@anthropic-ai/sdk/CVE-2026-34451/) verified **in-place** in `src/tools/memory/node.ts` using [LemmaScript](https://github.com/midspiral/LemmaScript) (Dafny backend). 1 verified function with 1 `ensures`, 0 errors. The same `ensures` rejects the pre-fix body that shipped in versions 0.79.0–0.80.x.

## CVE-2026-34451 — Memory Tool Path Validation Allows Sandbox Escape

The local-filesystem memory tool validated model-supplied paths with a string prefix check that did not append a trailing path separator. A model steered by prompt injection could supply a crafted path that resolved to a _sibling_ directory sharing the memory root's name as a prefix — e.g. with `memoryRoot = /sandbox/memory`, the path `/sandbox/memory-evil/secrets` passed `resolvedPath.startsWith(resolvedRoot)` — allowing reads and writes outside the sandboxed memory directory.

|             |                                                                                                                                                                                                           |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Advisory    | [GHSA / CVE-2026-34451](https://advisories.gitlab.com/pkg/npm/@anthropic-ai/sdk/CVE-2026-34451/)                                                                                                          |
| CWE         | CWE-22 (Path Traversal), CWE-41 (Path Equivalence)                                                                                                                                                        |
| Affected    | `@anthropic-ai/sdk` 0.79.0 – 0.80.x                                                                                                                                                                       |
| Fix         | [`0ac69b3`](https://github.com/anthropics/anthropic-sdk-typescript/commit/0ac69b3438ee9c96b21a7d3c39c07b7cdb6995d9) "memory: append path separator in validatePath prefix check", in 0.81.0 (Mar 31 2026) |
| Sibling CVE | [CVE-2026-34452](https://advisories.gitlab.com/pkg/pypi/anthropic/CVE-2026-34452/) — same feature in the Python SDK, different bug (race condition)                                                       |

The fix replaces

```ts
if (!resolvedPath.startsWith(resolvedRoot)) { … }
```

with

```ts
if (resolvedPath !== resolvedRoot && !resolvedPath.startsWith(resolvedRoot + path.sep)) { … }
```

at two call sites — `validatePath` and `validateNoSymlinkEscape`.

## What's Verified

A pure containment predicate factored out of the two duplicated inline checks, annotated and verified directly in `src/tools/memory/node.ts`:

```ts
function isInsideRoot(resolvedRoot: string, resolvedPath: string, sep: string): boolean {
  //@ verify
  //@ requires sep.length === 1
  //@ ensures \result === true ==> resolvedPath === resolvedRoot
  //@      || (resolvedPath.length > resolvedRoot.length
  //@          && resolvedPath.slice(0, resolvedRoot.length) === resolvedRoot
  //@          && resolvedPath.slice(resolvedRoot.length, resolvedRoot.length + 1) === sep)
  return resolvedPath === resolvedRoot || resolvedPath.startsWith(resolvedRoot + sep);
}
```

The postcondition is the **strict-containment** property the CVE was about: if `isInsideRoot` returns `true`, then the path is either the root itself, or extends it by a separator-prefixed suffix. The boundary character at position `resolvedRoot.length` _must_ be `sep` — the property that the buggy `startsWith(root)` form silently dropped.

`validatePath` and `validateNoSymlinkEscape` now call `isInsideRoot(resolvedRoot, resolvedPath, path.sep)` rather than open-coding the check. The async wrappers (`fs.realpath`, `path.resolve`, etc.) remain unverified — only the pure containment helper is in the verification surface.

```sh
$ ../LemmaScript/tools/check.sh dafny

Generated: src/tools/memory/node.dfy.gen
Created: src/tools/memory/node.dfy
Running dafny verify...

Dafny program verifier finished with 3 verified, 0 errors
```

## The Buggy Version Fails the Same Spec

To demonstrate that the postcondition isn't just restating the fix, we replaced the body with the pre-CVE-2026-34451 form (`return resolvedPath.startsWith(resolvedRoot)`) and re-ran the verifier. Dafny rejects it:

```
node.dfy(12,0): Error: a postcondition could not be proved on this return path
node.dfy(11,103): Related location: this is the postcondition that could not be proved
  ensures ((isInsideRoot(...) == true) ==>
    ((resolvedPath == resolvedRoot)
      || ((|resolvedPath| > |resolvedRoot|)
          && (resolvedPath[0..|resolvedRoot|] == resolvedRoot)
          && (resolvedPath[|resolvedRoot|..(|resolvedRoot| + 1)] == sep))))

Dafny program verifier finished with 2 verified, 1 error
```

The counterexample shape is exactly the attack: `resolvedRoot = "abc"`, `resolvedPath = "abcd"`. `startsWith` returns `true`, `resolvedPath !== resolvedRoot`, and `resolvedPath.slice(3, 4) === "d"` is not equal to `sep`. The postcondition forces the disjunction to fail and the proof obligation cannot be discharged — same predicate, two answers across the fix.

The fix shipped with two regression tests covering `sandbox/memory-evil` and `sandbox/memorysibling`. Neither would have caught a future variant on a different prefix collision. The `ensures` clause quantifies over _all_ `(resolvedRoot, resolvedPath, sep)` triples.

## Trust boundary

This is a narrow case study. The unverified surface includes:

- **All async / IO**: `fs.realpath`, `fs.access`, `path.resolve`, `path.join`, `path.dirname` — Node stdlib calls. The verification target is the pure boundary predicate that the async wrappers delegate to.
- **The symlink walker** in `validateNoSymlinkEscape`: the loop structure that walks up to the deepest existing ancestor is unverified. We only verify that _each_ containment check inside that loop uses the strict predicate.
- **`path.sep` itself**: passed as a `string` parameter with `|sep| == 1`. The Dafny model has no notion of OS-specific path separators; the requires-clause is the contract.
- **`path.resolve` correctness**: we assume `path.resolve` returns canonical absolute paths. If `path.resolve` itself were buggy (e.g., didn't normalize `..`), the predicate alone wouldn't save you. The sibling CVE-2026-34452 in the Python SDK is a race condition exactly at this boundary.
- **Everything else in `node.ts`**: command handlers, atomic-write helper, traversal — selective verification per LemmaScript SPEC §2.6. Only `//@ verify`-annotated functions are checked.

The verified predicate is necessary but not sufficient; it pins the _load-bearing string-prefix asymmetry_ that constituted the CVE.

## Setup

**Prerequisites:** [Dafny](https://github.com/dafny-lang/dafny) ≥ 4.x, Node.js ≥ 18.

```sh
git clone https://github.com/midspiral/LemmaScript.git ../LemmaScript
cd ../LemmaScript/tools && npm install && cd -
```

## Verify

```sh
../LemmaScript/tools/check.sh dafny
```

Reads `LemmaScript-files.txt` (currently lists `src/tools/memory/node.ts`), regenerates `src/tools/memory/node.dfy.gen`, and runs `dafny verify`. Functions without `//@ verify` are silently skipped.

## What's Next

- **Verify `path.resolve` semantics abstractly.** Model `path.resolve` as a function from string to string with the postcondition "result is absolute and free of `..`/`.` segments." Then prove that `isInsideRoot(resolve(root), resolve(p), sep) ==> resolve(p) does not have `..` outside root`. This brings the IO boundary inside the proof.
- **Cross-port to the Python SDK case study.** CVE-2026-34452 is a TOCTOU race in the same predicate; the property to prove there is concurrent safety, not just spatial containment.
