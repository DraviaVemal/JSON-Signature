import { createHash } from "crypto";

/**
 * @author Dravia vemal
 * @license MIT
 * @description Class used to create a normalised data pattern for JSON input and generate sha256 signature. This helps in maintaing the stability of signature for different order of same data.
 */
export class JsonSignature {
  private result: string[];

  constructor() {
    this.result = [];
  }

  private isDate = (value: any) => {
    const date = new Date(value);
    return !isNaN(date.getTime());
  };

  private isValidJSON = (jsonString: any) => {
    try {
      JSON.parse(JSON.stringify(jsonString));
      return true;
    } catch (error) {
      return false;
    }
  };

  private GetSortedKeys = (data: any): string[] => {
    return Object.keys(data).sort();
  };

  private ProcessJsonNode = (data: any): void => {
    this.result.push("{");
    const keys = this.GetSortedKeys(data);
    keys.forEach((key, index) => {
      if (index > 0) {
        this.result.push(",");
      }
      this.result.push(key.toString());
      this.result.push(":");
      if (
        typeof data[key] === "string" ||
        typeof data[key] === "number" ||
        typeof data[key] === "boolean" ||
        typeof data[key] === "undefined" ||
        typeof data[key] === "bigint" ||
        data[key] === null ||
        this.isDate(data[key])
      ) {
        this.result.push(data[key]?.toString() ?? '""');
      } else {
        this.ProcessMasterInput(data[key]);
      }
    });
    this.result.push("}");
  };

  private ProcessArrayNode = (data: any[]): void => {
    this.result.push("[");
    data.forEach((item, index) => {
      if (index > 0) {
        this.result.push(",");
      }
      if (
        typeof item === "string" ||
        typeof item === "number" ||
        typeof item === "boolean" ||
        typeof item === "undefined" ||
        typeof item === "bigint" ||
        item === null ||
        this.isDate(item)
      ) {
        this.result.push(item?.toString() ?? '""');
      } else {
        this.ProcessMasterInput(item);
      }
    });
    this.result.push("]");
  };

  private ProcessMasterInput = (data: any): void => {
    if (
      typeof data === "string" ||
      typeof data === "number" ||
      typeof data === "boolean" ||
      typeof data === "undefined" ||
      typeof data === "bigint" ||
      data === null ||
      this.isDate(data)
    ) {
      this.result.push(data?.toString() ?? '""');
    } else if (typeof data === "object") {
      if (Array.isArray(data)) {
        this.ProcessArrayNode(data);
      } else if (this.isValidJSON(data)) {
        this.ProcessJsonNode(data);
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
  };

  private NormaliseJsonToString = (data: any): string => {
    this.ProcessMasterInput(data);
    return this.result.join("");
  };

  public GetSignatureForPayload = (
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
       * TODO: This is yet to be implemented
       */
      ignoreArrayOrder?: boolean;
    }
  ): string => {
    return createHash(options?.hashType ?? "sha256")
      .update(this.NormaliseJsonToString(data))
      .digest(options?.digestType ?? "hex");
  };
}
