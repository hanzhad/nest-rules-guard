import { SetMetadata } from "@nestjs/common";
import { GetByFromRepo, Rules } from "./types";

export const RolesGuard = (
  roleList: string[],
  ruleList?: Rules,
  getByFromRepo?: GetByFromRepo,
) => SetMetadata('rules', { roleList, ruleList, getByFromRepo });
