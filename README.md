# SwiftIDA

This is a simple plugin for IDA to aid with reverse engineering languages that have multiple return values and non-standard calling conventions. It does this by defining a set of shortcuts to easily change a function's calling convention and make it return a multi-value tuple. Tested on Swift and Golang, but should work on many more languages too.

## Usage

Download `swift-ida.py` and drop it in your IDA's `plugins` folder. After that, simply right-click on a function definition and you will see the `SwiftIDA` menu.

![menu](docs/menu.png)

---

#### Before:

![before2](docs/before2.png)

![before1](docs/before1.png)

![before3](docs/before3.png)

---

#### After:

![after2](docs/after2.png)

![after1](docs/after1.png)

![after3](docs/after3.png)

## References

- https://github.com/swiftlang/swift/blob/main/docs/ABI/CallConvSummary.rst
- https://hex-rays.com/blog/igors-tip-of-the-week-107-multiple-return-values
- https://hex-rays.com/blog/igors-tip-of-the-week-51-custom-calling-conventions
- https://docs.hex-rays.com/user-guide/user-interface/menu-bar/edit/functions#set-function-item-type
