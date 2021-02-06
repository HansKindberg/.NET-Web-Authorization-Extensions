using System.Collections.Generic;

namespace HansKindberg.Web.Authorization.Configuration
{
	public class PolicyOptions
	{
		#region Properties

		public virtual IList<PermissionOptions> Permissions { get; } = new List<PermissionOptions>();
		public virtual IList<RoleOptions> Roles { get; } = new List<RoleOptions>();

		#endregion
	}
}