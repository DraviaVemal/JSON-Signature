import { createHash } from "crypto";

/**
 * @author Dravia vemal
 * @license MIT
 * @description Class used to create a normalised data pattern for JSON input and generate sha256 signature. This helps in maintaing the stability of signature for different order of same data.
 */
export class JsonSignature {
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

  private static GetSortedKeys = (data: any): string[] => {
    return Object.keys(data).sort();
  };

  private static ProcessJsonNode = (data: any): string[] => {
    const result: string[] = [];
    result.push("{");
    const keys = this.GetSortedKeys(data);
    keys.forEach((key, index) => {
      if (index > 0) {
        result.push(",");
      }
      result.push(key.toString());
      result.push(":");
      if (
        typeof data[key] === "string" ||
        typeof data[key] === "number" ||
        typeof data[key] === "boolean" ||
        typeof data[key] === "undefined" ||
        typeof data[key] === "bigint" ||
        data[key] === null ||
        this.isDate(data[key])
      ) {
        result.push(data[key]?.toString() ?? '""');
      } else {
        result.push(...this.ProcessMasterInput(data[key]));
      }
    });
    result.push("}");
    return result;
  };

  private static ProcessArrayNode = (data: any[]): string[] => {
    const result: string[] = [];
    const unSortedResult: string[] = [];
    result.push("[");
    data.forEach((item, index) => {
      if (
        typeof item === "string" ||
        typeof item === "number" ||
        typeof item === "boolean" ||
        typeof item === "undefined" ||
        typeof item === "bigint" ||
        item === null ||
        this.isDate(item)
      ) {
        unSortedResult.push(item?.toString() ?? '""');
      } else {
        unSortedResult.push(this.ProcessMasterInput(item).join(""));
      }
    });
    if (this.isIgnoreArrayPosition) {
      unSortedResult.sort();
    }
    result.push(unSortedResult.join());
    result.push("]");
    return result;
  };

  private static ProcessMasterInput = (data: any): string[] => {
    const result: string[] = [];
    if (
      typeof data === "string" ||
      typeof data === "number" ||
      typeof data === "boolean" ||
      typeof data === "undefined" ||
      typeof data === "bigint" ||
      data === null ||
      this.isDate(data)
    ) {
      result.push(data?.toString() ?? '""');
    } else if (typeof data === "object") {
      if (Array.isArray(data)) {
        result.push(...this.ProcessArrayNode(data));
      } else if (this.isValidJSON(data)) {
        result.push(...this.ProcessJsonNode(data));
      } else {
        throw new Error(
          "Input Payload has data type not supported by Json-Signature for signing."
        );
      }
    } else {
      throw new Error(
        "Input Payload has data type not supported by Json-Signature for signing."
      );
    }
    return result;
  };

  private static NormaliseJsonToString = (data: any): string => {
    return this.ProcessMasterInput(data).join("");
  };

  public static GetSignatureForPayload = (
    data: any,
    options?: {
      /**
       * Crypt encryption strategy
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
    const res = this.NormaliseJsonToString(data);
    console.log(res);
    return createHash(options?.hashType ?? "sha256")
      .update(res)
      .digest(options?.digestType ?? "hex");
  };
}
