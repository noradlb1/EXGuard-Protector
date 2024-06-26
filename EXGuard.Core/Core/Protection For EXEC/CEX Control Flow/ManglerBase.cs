﻿using System;
using System.Threading;
using System.Collections;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

using dnlib.DotNet.Emit;

namespace EXGuard.Core.EXECProtections.CEXCFlow
{
	public abstract class ManglerBase
	{
		protected static IEnumerable<InstrBlock> GetAllBlocks(ScopeBlock scope)
		{
			foreach (BlockBase child in scope.Children)
			{
				if (child is InstrBlock)
					yield return (InstrBlock)child;
				else
				{
					foreach (InstrBlock block in GetAllBlocks((ScopeBlock)child))
						yield return block;
				}
			}
		}

		public abstract void Mangle(CilBody body, ScopeBlock root, CEXContext ctx);
	}
}

