using System;
using System.Threading.Tasks;
using HansKindberg.Web.Authorization.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RegionOrebroLan.Logging.Extensions;

namespace HansKindberg.Web.Authorization
{
	[CLSCompliant(false)]
	public class AuthorizationPolicyProvider : DefaultAuthorizationPolicyProvider
	{
		#region Constructors

		public AuthorizationPolicyProvider(ILoggerFactory loggerFactory, IOptions<AuthorizationOptions> options, IOptionsMonitor<ExtendedAuthorizationOptions> optionsMonitor) : base(options)
		{
			this.Logger = (loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory))).CreateLogger(this.GetType());
			this.OptionsMonitor = optionsMonitor ?? throw new ArgumentNullException(nameof(optionsMonitor));
		}

		#endregion

		#region Properties

		protected internal virtual ILogger Logger { get; }
		protected internal virtual IOptionsMonitor<ExtendedAuthorizationOptions> OptionsMonitor { get; }

		#endregion

		#region Methods

		public override async Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
		{
			var policy = await base.GetPolicyAsync(policyName);

			var options = this.OptionsMonitor.CurrentValue;

			this.Logger.LogDebugIfEnabled($"{this.GetType().Name} is{(options.PolicyProviderEnabled ? null : " not")} enabled.");

			// ReSharper disable InvertIf
			if(options.PolicyProviderEnabled && policy == null)
			{
				this.Logger.LogDebugIfEnabled("Policy is null. Using extended policy-provider functionality to get policy.");

				policy = new AuthorizationPolicyBuilder().AddRequirements(new PermissionRequirement {Name = policyName}).Build();
			}
			// ReSharper restore InvertIf

			return policy;
		}

		#endregion
	}
}