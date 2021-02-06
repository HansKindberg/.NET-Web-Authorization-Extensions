using System.Collections.Generic;
using System.Security.Principal;
using System.Threading.Tasks;

namespace HansKindberg.Web.Authorization
{
	public interface IRoleProvider
	{
		#region Methods

		Task<IEnumerable<string>> GetRolesAsync(IPrincipal principal);

		#endregion
	}
}