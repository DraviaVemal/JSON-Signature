# JSON-Signature Generator

This package enables the generation of unique hash signatures for provided payloads.
It normalise json key order so the same payload data with different key order generates same key.

## Installation

You can install this package via pip:

```bash
npm i json-signature
```

## Usage

```javascript
import { JsonSignature } from "json-signature";

console.log(
  JsonSignature.GetSignatureForPayload(
    {
      key1: "value1",
      key2: "value2",
      array_key: [1, 2, 3],
    },
    {
      hashType: "sha256",
      digestType: "hex",
      ignoreArrayOrder: true,
    }
  )
);
```

## Contribution

Contributions are welcome! If you encounter issues or have suggestions for improvements, feel free to open an issue or submit a pull request on [GitHub](https://github.com/DraviaVemal/JSON-Signature/pulls).

## License

This package is licensed under the MIT License.

## Contact

For inquiries or support, please contact [contact@draviavemal.com](mailto:contact@draviavemal.com).
