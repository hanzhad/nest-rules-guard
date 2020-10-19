export declare interface Options {
  roleList: string[];
  ruleList: Rules;
  getByFromRepo: GetByFromRepo;
}

export declare interface Rules {
  [key: string]: RoleField;
}

export declare interface RoleField {
  dataFieldRules: Metadata;
  updatedDataPrivateRules?: Metadata;
}

export declare interface Metadata {
  [key: string]: string[] | boolean[] | number[];
}

export declare interface GetByFromRepo {
  service: string;
  action: string;
  searchFieldName: string;
  errorNotFound?: string;
}
