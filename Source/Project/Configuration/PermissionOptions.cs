using System;
using System.Collections.Generic;

namespace HansKindberg.Web.Authorization.Configuration
{
	public class PermissionOptions
	{
		#region Properties

		public virtual string Name { get; set; }
		public virtual ISet<string> Roles { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

		#endregion
	}
}