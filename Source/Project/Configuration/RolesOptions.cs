using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace HansKindberg.Web.Authorization.Configuration
{
	public class RolesOptions
	{
		#region Properties

		public virtual ISet<string> ExcludedRoleClaimTypes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
		{
			ClaimTypes.GroupSid
		};

		public virtual ISet<string> Providers { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
		public virtual WindowsRolesOptions Windows { get; set; } = new WindowsRolesOptions();

		#endregion
	}
}