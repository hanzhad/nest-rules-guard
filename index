// @ts-ignore
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  SetMetadata,
  Logger,
} from '@nestjs/common';
import * as _ from 'lodash';
import * as mongoose from 'mongoose';
import { ModuleRef, Reflector } from '@nestjs/core';
import { ExtractJwt } from 'passport-jwt';
import { JwtService } from '@nestjs/jwt';

export const RolesGuard = (
  roleList: string[],
  ruleList?: Rules,
  getByFromRepo?: GetByFromRepo,
) => SetMetadata('rules', { roleList, ruleList, getByFromRepo });

interface Options {
  roleList: string[];
  ruleList: Rules;
  getByFromRepo: GetByFromRepo;
}

interface Rules {
  [key: string]: RoleField;
}

interface RoleField {
  dataFieldRules: Metadata;
  updatedDataPrivateRules?: Metadata;
}

interface Metadata {
  [key: string]: string[] | boolean[] | number[];
}

interface GetByFromRepo {
  service: string;
  action: string;
  searchFieldName: string;
  errorNotFound?: string;
}

/** Usage Doc
 * in necessary controller, decorate endpoint by - @UseGuards(new RolesGuard(['admin']))
 * with roles witch can use this rout
 * as example - @UseGuards(new RolesGuard(['user', 'userPlus', 'root', 'admin']))
 * ! Warning
 * ! Only In controller
 * ! Only With @UseGuards(AuthGuard()) decorator
 * ! must be pleased before @UseGuards(AuthGuard())
 * ! Because Nest run @UseGuards from bottom to top
 *
 * Second argument Rules - optional
 * Rules, this is an object with an enumeration of roles (as keys)
 * the value is an object whose keys are checking the corresponding keys in data and checking for includes
 * as example - @UseGuards(new RolesGuard(
 *   ['admin'],
 *   {
 *      dataFieldRules: { - rules for request data
 *        roles: ['user', 'userPlus', 'provider'],
 *        name: ['new'],
 *      },
 *      updatedDataPrivateRules: { - rules for repo data, will be ignored if 3rd argument missing
 *        email: ['a@sss.com'],
 *        roles: ['user', 'userPlus'],
 *        isActive: [ false ]
 *      },
 *   },
 *   { // Optional argument, if exist go to the service and call action wth argument which grep from body/query/params by searchFieldName
 *      service: 'UsersService', - Name of service which will be import // ! Must be import service with current name in this file
 *      action: 'getById', - Action func on service which will be called
 *      searchFieldName: '_id', - Key of data in request for action param
 *      errorNotFound: 'ERROR!!!! BLYAT', - Error what will be called if service.action return undef or null
 *   },
 * ))
 * in this example, the admin can manipulate the user data as follows:
 * roles can be any contain ['user', 'userPlus', 'provider'] or less
 * name can be only 'new'
 * isActive can be only false
 * ! Warning
 * ! Rules must be an array type
 */

@Injectable()
export class RolesGuardClass implements CanActivate {
  private readonly logger = new Logger(RolesGuardClass.name);
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

      // tslint:disable-next-line: no-string-literal
    return { _id: user['_id'], roles: user['roles'] };
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

          if ((string.search('id') !== -1) || (string.search('Id') !== -1)) {
            try {
              mongoose.Types.ObjectId(data[searchInfoObject.searchFieldName]);
            } catch (e) {
              throw new HttpException(`${searchInfoObject.searchFieldName} field must be a mongoId`, HttpStatus.BAD_REQUEST);
            }
          }

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
