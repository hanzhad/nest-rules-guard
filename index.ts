import { RolesGuard } from "./roles-guard";
import { RolesGuardService } from "./roles-guard.service";

/** Usage Doc
 * in necessary controller, decorate endpoint by - @UseGuards(new RolesGuardService(['admin']))
 * with roles witch can use this rout
 * as example - @UseGuards(new RolesGuardService(['user', 'userPlus', 'root', 'admin']))
 * ! Warning
 * ! Only In controller
 * ! Only With @UseGuards(AuthGuard()) decorator
 * ! must be pleased before @UseGuards(AuthGuard())
 * ! Because Nest run @UseGuards from bottom to top
 *
 * Second argument Rules - optional
 * Rules, this is an object with an enumeration of roles (as keys)
 * the value is an object whose keys are checking the corresponding keys in data and checking for includes
 * as example - @UseGuards(new RolesGuardService(
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
export default RolesGuard;
export { RolesGuardService };
