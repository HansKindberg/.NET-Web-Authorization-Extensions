using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IntegrationTests
{
	// ReSharper disable All
	[TestClass]
	[SuppressMessage("Naming", "CA1716:Identifiers should not match keywords")]
	public static class Global
	{
		#region Fields

		public const string DefaultEnvironment = "Integration-test";
		public static readonly string ProjectDirectoryPath = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory).Parent.Parent.Parent.FullName;

		#endregion
	}
	// ReSharper restore All
}