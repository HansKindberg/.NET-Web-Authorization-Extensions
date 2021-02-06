using System.Collections.Generic;
using System.Security.Principal;
using System.Threading.Tasks;

namespace HansKindberg.Web.Authorization
{
	public interface IPermissionProvider
	{
		#region Methods

		Task<IEnumerable<string>> GetPermissionsAsync(IPrincipal principal, IEnumerable<string> roles);

		#endregion
	}
}