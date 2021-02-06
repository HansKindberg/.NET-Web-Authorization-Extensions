using System;
using System.Collections.Generic;

namespace HansKindberg.Web.Authorization.Configuration
{
	public class PermissionsOptions
	{
		#region Properties

		public virtual ISet<string> Providers { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

		#endregion
	}
}