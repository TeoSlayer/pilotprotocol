# Third-Party Licenses

This file lists third-party code included in the Pilot Protocol source tree
and the license under which each is redistributed.

The core protocol (networking, tunnels, registry, daemon, CLI) uses only the
Go standard library. Third-party dependencies are scoped to specific
subsystems listed below.

---

## github.com/expr-lang/expr

- **Version:** v1.17.8
- **Used in:** `pkg/policy/` (policy expression engine — compiles and evaluates
  user-supplied match expressions from policy documents)
- **License:** MIT
- **Upstream:** https://github.com/expr-lang/expr

```
MIT License

Copyright (c) 2018 Anton Medvedev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
