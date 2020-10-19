import * as _ from 'lodash';
import { CanActivate, ExecutionContext, HttpException, HttpStatus, Injectable, Logger } from "@nestjs/common";
import { ModuleRef, Reflector } from "@nestjs/core";
import { JwtService } from "@nestjs/jwt";
import { ExtractJwt } from 'passport-jwt';
import { Metadata, Options } from "./types";

@Injectable()
export class RolesGuardService implements CanActivate {
  private readonly logger = new Logger(RolesGuardService.name);
  /** RoleAccessStrategy */

  service?: any;
  /**
   * roleStrategy
   */
  constructor(
    private readonly reflector: Reflector,
    private moduleRef: ModuleRef,
    private readonly jwtService: JwtService,
  ) {
  }

  /**
   * decryptToken - decrypt token structure
   * @param {ExecutionContext} context - guard context
   * @returns {Promise<boolean>} - boolean endpoint access
   */
  decryptToken(
    context: ExecutionContext,
  ): any {
    const request = context.switchToHttp().getRequest();
    let user;
    try {
      const getToken = ExtractJwt.fromAuthHeaderAsBearerToken();
      const token = getToken(request);
      user = this.jwtService.decode(token);
    } catch (error) {
      throw new HttpException({
        code: 4010000,
        message: `Unauthorized`,
      }, HttpStatus.UNAUTHORIZED);
    }
    if (!user) {
      throw new HttpException({
        code: 4010001,
        message: `Unauthorized`,
      }, HttpStatus.UNAUTHORIZED);
    }

    return user;
  }

  /**
   * canActivate - role and decrypt token structure
   * @param {ExecutionContext} context - guard context
   * @returns {Promise<boolean>} - boolean endpoint access
   */
  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean> {
    const options = this.reflector.get<Options>('rules', context.getHandler());

    if (!options) {
      return true;
    }

    const user = this.decryptToken(context);
    const request = context.switchToHttp().getRequest();
    request.user = user;
    let access = false;
    for (const reqUserRole of user.roles) {
      if (_.includes(options.roleList, reqUserRole)) {
        if (options.ruleList) {
          access = await this.checkRules(request, options, user);
        }
        return true;
      }
    }
    return access;
  }

  /**
   * checkRules - check whether this role performs an operation that complies with the rules
   * @returns {Promise<boolean>} - boolean endpoint access
   */
  async checkRules(
    request: any,
    options: Options,
    user: { _id: string, roles: string[] },
  ): Promise<boolean> {
    const userRoleList = user.roles;
    const { ruleList } = options;

    // Pick data from request // ! Be careful, identical variable naming will be rewritten depending on priority.
    const data = {};

    _.assignIn(data, request.params); // Low priority
    _.assignIn(data, request.query); // Medium priority
    _.assignIn(data, request.body); // Hight priority

    let permission = false;

    for (const userRoleListKey of userRoleList) { // For in Roles the one who performs the operation
      if (!ruleList[userRoleListKey]) {
        continue;
      }

      const { dataFieldRules } = ruleList[userRoleListKey];

      const { updatedDataPrivateRules } = ruleList[userRoleListKey];

      if (!dataFieldRules && !updatedDataPrivateRules) {
        permission = true;
        break;
      }
      permission = this.validateRules(dataFieldRules, data);

      if (permission) {
        const searchInfoObject = options.getByFromRepo;
        if (searchInfoObject) {
          permission = false;
          // tslint:disable-next-line: variable-name
          const string = searchInfoObject.searchFieldName;

          if (!data[searchInfoObject.searchFieldName]) {
            throw new HttpException(`${string} is required by rules`, HttpStatus.BAD_REQUEST);
          }

          // if ((string.search('id') !== -1) || (string.search('Id') !== -1)) {
          //   try {
          //     mongoose.Types.ObjectId(data[searchInfoObject.searchFieldName]);
          //   } catch (e) {
          //     throw new HttpException(`${searchInfoObject.searchFieldName} field must be a mongoId`, HttpStatus.BAD_REQUEST);
          //   }
          // }

          try {
            this.service = this.moduleRef.get(searchInfoObject.service, { strict: false });
          } catch (error) {
            this.logger.error(`"${searchInfoObject.service}": service is not found in dependency nest`);
            this.logger.error(`Make sure ${request.url} rules is written correct`);
            throw new HttpException(`"${searchInfoObject.service}": service is not found in dependency`, HttpStatus.INTERNAL_SERVER_ERROR);
          }

          let updatedDataPrivate;
          try {
            updatedDataPrivate = await this.service[searchInfoObject.action](data[searchInfoObject.searchFieldName]);
          } catch (error) {
            if (JSON.stringify(error) === '{}') {
              this.logger.error(`"${searchInfoObject.service}.${searchInfoObject.action}": is not found in dependency nest`);
              this.logger.error(`Make sure ${request.url} rules is written correct`);
              throw new HttpException(
                `"${searchInfoObject.service}.${searchInfoObject.action}": service is not found in dependency`,
                HttpStatus.INTERNAL_SERVER_ERROR,
              );
            }
            throw error;
          }

          if (!updatedDataPrivate) {
            throw new HttpException(
              `${searchInfoObject.errorNotFound || `Data not found`}`,
              HttpStatus.BAD_REQUEST);
          }
          permission = this.validateRules(updatedDataPrivateRules, updatedDataPrivate);
        }
      }

    }
    return permission;
  }

  /**
   * validateRules - validate whether this role performs an operation that complies with the rules
   * @param {Metadata} dataRule - data rules
   * @param {object} dataObject - data
   * @returns {boolean} - boolean endpoint access
   */
  validateRules(dataRule: Metadata, dataObject: object): boolean {
    let response = true;
    // tslint:disable-next-line: forin
    for (const roleRuleKey in dataRule) {
      let updatingDataFieldList = dataObject[roleRuleKey];
      let permissibleFieldsList = dataRule[roleRuleKey];

      if (typeof updatingDataFieldList === 'string' || typeof updatingDataFieldList === 'boolean') {
        updatingDataFieldList = [updatingDataFieldList];
      }

      if (typeof permissibleFieldsList === 'string' || typeof permissibleFieldsList === 'boolean') {
        permissibleFieldsList = [permissibleFieldsList];
      }

      if (!updatingDataFieldList) {
        continue;
      }

      for (const i of updatingDataFieldList) {
        if (!_.includes(permissibleFieldsList, i)) {
          response = false;
          break;
        }
      }
    }
    return response;
  }
}
