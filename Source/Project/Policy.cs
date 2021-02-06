using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace HansKindberg.Web.Authorization
{
	[SuppressMessage("Naming", "CA1724:Type names should not match namespaces")]
	public class Policy : IPolicy
	{
		#region Properties

		IEnumerable<string> IPolicy.Permissions => this.Permissions;
		public virtual ISet<string> Permissions { get; } = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
		IEnumerable<string> IPolicy.Roles => this.Roles;
		public virtual ISet<string> Roles { get; } = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

		#endregion
	}
}