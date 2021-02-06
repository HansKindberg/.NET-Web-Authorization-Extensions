using Microsoft.AspNetCore.Authorization;

namespace HansKindberg.Web.Authorization
{
	public class PermissionRequirement : IAuthorizationRequirement
	{
		#region Properties

		public virtual string Name { get; set; }

		#endregion
	}
}