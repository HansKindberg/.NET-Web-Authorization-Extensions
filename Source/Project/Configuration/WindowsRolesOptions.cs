using System;

namespace HansKindberg.Web.Authorization.Configuration
{
	public class WindowsRolesOptions
	{
		#region Properties

		public virtual bool BuiltInRolesEnabled { get; set; }
		public virtual TimeSpan CacheDuration { get; set; } = TimeSpan.FromMinutes(15);
		public virtual bool CacheEnabled { get; set; }
		public virtual bool MachineRolesEnabled { get; set; }

		#endregion
	}
}