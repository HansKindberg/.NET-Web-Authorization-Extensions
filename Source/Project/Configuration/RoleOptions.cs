using System;
using System.Collections.Generic;

namespace HansKindberg.Web.Authorization.Configuration
{
	public class RoleOptions
	{
		#region Properties

		public virtual string Name { get; set; }

		/// <summary>
		/// The user-identifiers, subjects, that maps users to this role.
		/// </summary>
		public virtual ISet<string> Users { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

		#endregion
	}
}