import { createHash } from "crypto";

/**
 * @author Dravia vemal
 * @license MIT
 * @description Class used to create a normalised data pattern for JSON input and generate sha256 signature. This helps in maintaing the stability of signature for different order of same data.
 */
export class JsonSignature {
  /**
   * @description No need to create object item.
   * @example ```javascript
        import { JsonSignature } from "json-signature";

        console.log(
          JsonSignature.GetSignatureForData(
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
   */
  private constructor() { }

  private static UNSUPPORTED_ERROR_MSG = "Input Payload has data type not supported by Json-Signature for signing.";

  private static isIgnoreArrayPosition: boolean = false;
  private static isDate = (value: any) => {
    const date = new Date(value);
    return !isNaN(date.getTime());
  };

  private static isValidJSON = (jsonString: any) => {
    try {
      JSON.parse(JSON.stringify(jsonString));
      return true;
    } catch (error) {
      return false;
    }
  };

  private static isSupportedType = (data: any) => {
    return typeof data === "string" ||
      typeof data === "number" ||
      typeof data === "boolean" ||
      typeof data === "undefined" ||
      typeof data === "bigint" ||
      data === null ||
      this.isDate(data)
  }

  private static GetSortedKeys = (data: any): string[] => {
    return Object.keys(data).sort();
  };

  private static ProcessJsonNode = (data: any): string[] => {
    const result: string[] = ["{"];
    this.GetSortedKeys(data).forEach((key, index) => {
      if (index > 0) {
        result.push(",");
      }
      result.push(key.toString(), ":");
      if (this.isSupportedType(data[key])) {
        result.push(data[key]?.toString() ?? '""');
      } else {
        result.push(...this.ProcessMasterInput(data[key]));
      }
    });
    result.push("}");
    return result;
  };

  private static ProcessArrayNode = (data: any[]): string[] => {
    const result: string[] = ["["];
    const unSortedResult: string[] = [];
    data.forEach((item) => {
      if (this.isSupportedType(item)) {
        unSortedResult.push(item?.toString() ?? '""');
      } else {
        unSortedResult.push(this.ProcessMasterInput(item).join(""));
      }
    });
    result.push(this.isIgnoreArrayPosition ? unSortedResult.sort().join() : unSortedResult.join(), "]");
    return result;
  };

  private static ProcessMasterInput = (data: any): string[] => {
    const result: string[] = [];
    if (this.isSupportedType(data)) {
      result.push(data?.toString() ?? '""');
    } else if (typeof data === "object") {
      if (Array.isArray(data)) {
        result.push(...this.ProcessArrayNode(data));
      } else if (this.isValidJSON(data)) {
        result.push(...this.ProcessJsonNode(data));
      } else {
        throw new Error(this.UNSUPPORTED_ERROR_MSG);
      }
    } else {
      throw new Error(this.UNSUPPORTED_ERROR_MSG);
    }
    return result;
  };

  private static NormaliseJsonToString = (data: any): string => {
    return this.ProcessMasterInput(data).join("");
  };

  /**
   * Generate same hash signature for provided input irrespective of key orders of JSON
   * @param data Any input payload that needs hash sign
   * @param options Provides additional option to customise
   * @returns hash string
   */
  public static GetSignatureForData = (
    /**
     * Input Data to be signed
     */
    data: any,
    /**
     * Available customization options
     */
    options?: {
      /**
       * Crypt encryption algorithms use flags supported by OpenSSL
       * @default sha256
       */
      hashType?: string;
      /**
       * Digest hash result is encoded into once of the types
       * @default hex
       */
      digestType?: "base64" | "base64url" | "hex" | "binary";
      /**
       * Skips preserving the array position when signing, ensuring that changes in the array position of the same data result in different signatures.
       */
      ignoreArrayOrder?: boolean;
    }
  ): string => {
    this.isIgnoreArrayPosition = options?.ignoreArrayOrder ?? false;
    return createHash(options?.hashType ?? "sha256")
      .update(this.NormaliseJsonToString(data))
      .digest(options?.digestType ?? "hex");
  };
}
