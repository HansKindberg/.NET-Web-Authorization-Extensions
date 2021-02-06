// unset

using System.Security.Principal;
using System.Threading.Tasks;

namespace HansKindberg.Web.Authorization
{
	public interface IAuthorizationResolver
	{
		#region Methods

		Task<IPolicy> GetPolicyAsync(IPrincipal principal);
		Task<bool> HasPermissionAsync(string permission, IPrincipal principal);
		Task<bool> IsInRoleAsync(IPrincipal principal, string role);

		#endregion
	}
}