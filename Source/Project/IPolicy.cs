using System.Collections.Generic;

namespace HansKindberg.Web.Authorization
{
	public interface IPolicy
	{
		#region Properties

		IEnumerable<string> Permissions { get; }
		IEnumerable<string> Roles { get; }

		#endregion
	}
}