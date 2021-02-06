using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace HansKindberg.Web.Authorization
{
	[CLSCompliant(false)]
	public abstract class PermissionProvider : IPermissionProvider
	{
		#region Constructors

		protected PermissionProvider(IClaimsPrincipalHelper claimsPrincipalHelper, ILoggerFactory loggerFactory)
		{
			this.ClaimsPrincipalHelper = claimsPrincipalHelper ?? throw new ArgumentNullException(nameof(claimsPrincipalHelper));
			this.Logger = (loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory))).CreateLogger(this.GetType());
		}

		#endregion

		#region Properties

		protected internal virtual IClaimsPrincipalHelper ClaimsPrincipalHelper { get; }
		protected internal virtual ILogger Logger { get; }

		#endregion

		#region Methods

		[SuppressMessage("Style", "IDE0066:Convert switch statement to expression")]
		public virtual async Task<IEnumerable<string>> GetPermissionsAsync(IPrincipal principal, IEnumerable<string> roles)
		{
			// ReSharper disable ConvertSwitchStatementToSwitchExpression
			switch(principal)
			{
				case null:
					throw new ArgumentNullException(nameof(principal));
				case ClaimsPrincipal claimsPrincipal:
					return await this.GetPermissionsInternalAsync(claimsPrincipal, roles);
				default:
					return Enumerable.Empty<string>();
			}
			// ReSharper restore ConvertSwitchStatementToSwitchExpression
		}

		protected internal abstract Task<ISet<string>> GetPermissionsInternalAsync(ClaimsPrincipal claimsPrincipal, IEnumerable<string> roles);

		#endregion
	}
}