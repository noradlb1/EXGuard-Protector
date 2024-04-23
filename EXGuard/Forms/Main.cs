using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Text;
using System.Data;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;
using System.Globalization;
using System.IO.Compression;
using System.ComponentModel;
using System.Collections.Generic;

using dnlib.DotNet;
using dnlib.DotNet.MD;
using dnlib.DotNet.Writer;

using DevExpress.Utils;
using DevExpress.XtraEditors;
using DevExpress.XtraEditors.Controls;

using EXGuard.Services;
using EXGuard.Internal;
using EXGuard.Properties;

using EXGuard.Core;
using EXGuard.Core.EXECProtections;
using EXGuard.Core.EXECProtections._Mutation;
using EXGuard.Core.EXECProtections.CEXCFlow;

namespace EXGuard
{
    public partial class Main : XtraForm
    {
        public ModuleDefMD EXECModule
        {
            get;
            private set;
        }

        public ModuleDefMD mscorlib
        {
            get;
            private set;
        }

        public List<CheckedListBoxItem> TempMethodList
        {
            get;
            private set;
        }

        private void LOG(string text, bool newline = false)
        {
            LogBox.Items.Add(text);

            if (newline)
                LogBox.Items.Add(Environment.NewLine);
        }

        private void _DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effect = DragDropEffects.Copy;
            }
        }

        public Main()
        {
            mscorlib = ModuleDefMD.Load(typeof(string).Module);

            InitializeComponent();
            EXGTabControl.ShowTabHeader = DefaultBoolean.False;
        }

        private static void Protect(Main _this)
        {
            _this.LogBox.Items.Clear();

            _this.EXGTabControl.SelectedTabPage = _this.LogsTabPage;

            _this.ShowMainPageCheckButton.Enabled = false;
            _this.ShowProtectionsPageCheckButton.Enabled = false;
            _this.ShowFunctionsPageCheckButton.Enabled = false;
            _this.ShowRuntimeSettingsPageCheckButton.Enabled = false;
            _this.ShowLogsPageAndProtectCheckButton.Enabled = false;
            _this.ShowAboutPageCheckButton.Enabled = false;

            #region Copyright
            //////////////////////////////////////////////////////////
            _this.LOG($"EXGuard .NET Virtualize v{Resources.Version}");
            _this.LOG("Copyright © HolyEX 2020-2022", true);
            //////////////////////////////////////////////////////////
            #endregion

            #region Module File Info
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            _this.LOG($"Assembly: {_this.AsmBox.Text}", true);
            _this.LOG("Destination Assembly: " + _this.DestinationBox.Text, true);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region SNK Info
            //////////////////////////////////////////////////////////////////////////////////
            if (!_this.ActiveSNK.IsOn)
            {
                _this.LOG("Sign The Assembly: False", true);
            }
            else
            {
                _this.LOG("Strong Name Key (SNK) File Location: " + _this.SNKLocationBox.Text, true);
                _this.LOG("Strong Name Key (SNK) Password: " + _this.SNKPasswordBox.Text, true);
            }
            //////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region RT Mode Info
            //////////////////////////////////////////////////////////////////////////////////
            _this.LOG($"Runtime Name: {_this.RuntimeNameBox.Text}", true);
            //////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region Protection Options Info
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            _this.LOG("-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

            // Antis
            if (_this.AntiDebugToggle.IsOn)
                _this.LOG("Anti Debug: True");
            else
                _this.LOG("Anti Debug: False");

            if (_this.AntiDumpToggle.IsOn)
                _this.LOG("Anti Dump: True");
            else
                _this.LOG("Anti Dump: False");

            if (_this.AntiVMToggle.IsOn)
                _this.LOG("Anti Virtual Machine: True");
            else
                _this.LOG("Anti Virtual Machine: False");

            if (_this.AntiILDasmToggle.IsOn)
                _this.LOG("Anti ILDasm: True");
            else
                _this.LOG("Anti ILDasm: False");

            if (_this.AntiDe4dotToggle.IsOn)
                _this.LOG("Anti De4dot: True");
            else
                _this.LOG("Anti De4dot: False");

            if (_this.AntiDnspyToggle.IsOn)
                _this.LOG("Anti Dnspy: True");
            else
                _this.LOG("Anti Dnspy: False");

            if (_this.AntiWebDebuggersToggle.IsOn)
                _this.LOG("Anti Web Debuggers: True");
            else
                _this.LOG("Anti Web Debuggers: False");

            //////////////////////////////////////////////////////////////////////////////////

            // Misc Part 1
            if (_this.VirtualizeAllStringsToggle.IsOn)
                _this.LOG("Virtualize All Strings: True");
            else
                _this.LOG("Virtualize All Strings: False");

            if (_this.VirtualizeAllNumbersToggle.IsOn)
                _this.LOG("Virtualize All Numbers: True");
            else
                _this.LOG("Virtualize All Numbers: False");

            if (_this.VirtualizeAllReferenceProxiesToggle.IsOn)
                _this.LOG("Virtualize All Reference Proxies: True");
            else
                _this.LOG("Virtualize All Reference Proxies: False");

            if (_this.CodeMutationToggle.IsOn)
                _this.LOG("Code Mutation: True");
            else
                _this.LOG("Code Mutation: False");

            if (_this.CodeFlowToggle.IsOn)
                _this.LOG("Code Flow: True");
            else
                _this.LOG("Code Flow: False");
            //////////////////////////////////////////////////////////////////////////////////

            // Misc Part 2
            if (_this.ResourceCompressAndEncryptToggle.IsOn)
                _this.LOG("Resource Compress and Encrypt: True");
            else
                _this.LOG("Resource Compress and Encrypt: False");
            //////////////////////////////////////////////////////////////////////////////////

            _this.LOG("-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------", true);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region Virtualize Method Info
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            _this.LOG("-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

            foreach (CheckedListBoxItem method in _this.FunctionsCheckList.CheckedItems)
                _this.LOG($"[Virtualize] \"{method.Value}\"");

            _this.LOG("-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------", true);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

            var module = ModuleDefMD.Load(_this.AsmBox.Text);
            var methods = new HashSet<MethodDef>();

            foreach (CheckedListBoxItem method in _this.FunctionsCheckList.CheckedItems)
                methods.Add((MethodDef)method.Tag);

            module.AssemblyReferencesAdder();

            //#region Find Costura and Extract
            /////////////////////////////////////////////////////////////////////
            //CosturaFodyDecompressor.ExtractDLLs(module, Vanilla_File_Dir);
            /////////////////////////////////////////////////////////////////////
            //#endregion

            #region Protections
            //////////////////////////////////////////////////////////////////////////////////////////////////////
            #region Virtualize All Reference Proxies
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            if (_this.VirtualizeAllReferenceProxiesToggle.IsOn)
            {
                RPNormal.Execute(module);

                foreach (var refmd in RPNormal.ProxyMethods)
                    methods.Add(refmd);
            }
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region Anti Debug and Anti VM
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            if (_this.AntiDebugToggle.IsOn)
                foreach (var antdbg in AntiDebug_Inject.Execute(module))
                    methods.Add(antdbg);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region Anti Dump
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            if (_this.AntiDumpToggle.IsOn)
                foreach (var antdmp in AntiDump_Inject.Execute(module))
                    methods.Add(antdmp);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region Anti ILDasm
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            if (_this.AntiILDasmToggle.IsOn)
                AntiILDasm_Inject.Execute(module);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region Anti De4dot
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            if (_this.AntiDe4dotToggle.IsOn)
                AntiDe4dot_Inject.Execute(module);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region Anti Dnspy
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            if (_this.AntiDnspyToggle.IsOn)
                foreach (var antdnspy in AntiDnspy_Inject.Execute(module))
                    methods.Add(antdnspy);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region Anti Web Debuggers
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            if (_this.AntiWebDebuggersToggle.IsOn)
                foreach (var antwebdbg in AntiWebDebuggers_Inject.Execute(module))
                    methods.Add(antwebdbg);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region Resource Protection
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            if (_this.ResourceCompressAndEncryptToggle.IsOn)
                foreach (var resprot in ResourceProt_Inject.Execute(module))
                    methods.Add(resprot);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region Virtualize All Strings
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            if (_this.VirtualizeAllStringsToggle.IsOn)
                foreach (var hcst in module.Types.ToArray())
                    if (hcst != module.GlobalType)
                        foreach (var hcsm in hcst.Methods.ToArray())
                            if (!methods.Contains(hcsm))
                                new HideCallString(module).Execute(hcst, hcsm);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region Virtualize All Numbers
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            if (_this.VirtualizeAllNumbersToggle.IsOn)
                foreach (var hcst in module.Types.ToArray())
                    if (hcst != module.GlobalType)
                        foreach (var hcsm in hcst.Methods.ToArray())
                            if (!methods.Contains(hcsm))
                                new HideCallNumber(module).Execute(hcst, hcsm);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region Code Flow
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            if (_this.CodeFlowToggle.IsOn)
                foreach (var mtt in module.Types.ToArray())
                    if (mtt != module.GlobalType)
                        foreach (var mtm in mtt.Methods.ToArray())
                            if (!RPNormal.ProxyMethods.Contains(mtm) && !methods.Contains(mtm))
                                CEXControlFlow.Execute(mtm, 1);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region Code Mutation
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            if (_this.CodeMutationToggle.IsOn)
                foreach (var mtt in module.Types.ToArray())
                    if (mtt != module.GlobalType)
                        foreach (var mtm in mtt.Methods.ToArray())
                            if (!RPNormal.ProxyMethods.Contains(mtm))
                                MutationProt.Execute(module, mtm);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region Virtualize
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            new EXGuardTask().Exceute(module, methods, _this.DestinationBox.Text, _this.RuntimeNameBox.Text, _this.SNKLocationBox.Text, _this.SNKPasswordBox.Text);
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion
            //////////////////////////////////////////////////////////////////////////////////////////////////////
            #endregion

            #region Extracted file Log
            //////////////////////////////////////////////////////////////////////////////////////////////////
            _this.LOG($"Extracted: \"{_this.DestinationBox.Text}\"");
            /////////////////////////////////////////*////////////////////////////////////////////////////////
            #endregion

            #region Protection Done Log
            ////////////////////////////
            _this.LOG("Protection Done!");
            ////////////////////////////
            #endregion

            // Enable Show Page Buttons
            _this.ShowMainPageCheckButton.Enabled = true;
            _this.ShowProtectionsPageCheckButton.Enabled = true;
            _this.ShowFunctionsPageCheckButton.Enabled = true;
            _this.ShowRuntimeSettingsPageCheckButton.Enabled = true;
            _this.ShowLogsPageAndProtectCheckButton.Enabled = true;
            _this.ShowAboutPageCheckButton.Enabled = true;
            ////////////////////////////////////////////////////////

            methods.Clear();
            module.Dispose();

            ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////      
        }

        private void ResetSettings()
        {
            EXECModule?.Dispose();
            TempMethodList?.Clear();

            ShowMainPageCheckButton.Enabled = true;
            ShowProtectionsPageCheckButton.Enabled = true;
            ShowFunctionsPageCheckButton.Enabled = true;
            ShowRuntimeSettingsPageCheckButton.Enabled = true;
            ShowLogsPageAndProtectCheckButton.Enabled = false;
            ShowAboutPageCheckButton.Enabled = true;

            AsmBox.Text = string.Empty;
            DestinationBox.Text = string.Empty;

            ActiveSNK.IsOn = false;
            SNKLocationBox.Text = string.Empty;

            VirtualizeAllFunctionsToggle.IsOn = false;
            FunctionSearchBox.Text = string.Empty;
            FunctionsCheckList.Items.Clear();

            AntiDebugToggle.IsOn = false;
            AntiDumpToggle.IsOn = false;
            AntiVMToggle.IsOn = false;
            AntiILDasmToggle.IsOn = false;
            AntiDe4dotToggle.IsOn = false;
            AntiDnspyToggle.IsOn = false;
            AntiWebDebuggersToggle.IsOn = false;
            AntiDe4dotToggle.IsOn = false;

            VirtualizeAllStringsToggle.IsOn = false;
            VirtualizeAllNumbersToggle.IsOn = false;
            VirtualizeAllReferenceProxiesToggle.IsOn = false;
            CodeMutationToggle.IsOn = false;
            CodeFlowToggle.IsOn = false;

            ResourceCompressAndEncryptToggle.IsOn = false;
        }

        private void AddMethodsToFunctionsCheckList()
        {
            TempMethodList = new List<CheckedListBoxItem>();
            FunctionsCheckList.Items.Clear();

            foreach (TypeDef type in EXECModule.GetTypes())
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (method.IsPinvokeImpl || method.IsUnmanagedExport || method.IsUnmanaged || !method.HasBody || method.HasGenericParameters ||
                        method == EXECModule.GlobalType.FindOrCreateStaticConstructor())
                        continue;

                    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                    var mdFullName = string.Empty;

                    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                    if (method.IsPublic)
                        mdFullName += "public ";

                    if (method.IsPrivate)
                        mdFullName += "private ";

                    if (method.IsAssembly)
                        mdFullName += "internal ";

                    if (method.IsFamily)
                        mdFullName += "protected ";

                    if (method.IsFamilyOrAssembly)
                        mdFullName += "protected internal ";

                    if (method.IsAbstract)
                        mdFullName += "abstract ";

                    if (method.IsVirtual)
                        mdFullName += "virtual ";

                    if (method.IsStatic)
                        mdFullName += "static ";

                    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                    var retTypeName = new StringBuilder();

                    #region Read Return Type Namespace and Name
                    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                    if (method.ReturnType.IsByRef)
                    {
                        var refKeywordRemovedMDName = method.ReturnType.TypeName.Substring(0, method.ReturnType.TypeName.Length - 1);
                        var refKeywordANDptrSymbolRemovedMDName = refKeywordRemovedMDName.Substring(0, refKeywordRemovedMDName.Length - 1);

                        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                        retTypeName.Append("ref ");

                        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                        if (method.ReturnType.Module != mscorlib)
                        {
                            if (refKeywordRemovedMDName != "Byte" && refKeywordRemovedMDName != "SByte" && refKeywordRemovedMDName != "Boolean" &&
                                refKeywordRemovedMDName != "UInt16" && refKeywordRemovedMDName != "Int16" && refKeywordRemovedMDName != "Char" &&
                                refKeywordRemovedMDName != "UInt32" && refKeywordRemovedMDName != "Int32" && refKeywordRemovedMDName != "UInt64" &&
                                refKeywordRemovedMDName != "Int64" && refKeywordRemovedMDName != "Single" && refKeywordRemovedMDName != "Double" &&
                                refKeywordRemovedMDName != "IntPtr" && refKeywordRemovedMDName != "UIntPtr" && refKeywordRemovedMDName != "String" &&
                                refKeywordRemovedMDName != "Object" && refKeywordRemovedMDName != "Void" &&

                                ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                refKeywordANDptrSymbolRemovedMDName != "Byte" && refKeywordANDptrSymbolRemovedMDName != "SByte" && refKeywordANDptrSymbolRemovedMDName != "Boolean" &&
                                refKeywordANDptrSymbolRemovedMDName != "UInt16" && refKeywordANDptrSymbolRemovedMDName != "Int16" && refKeywordANDptrSymbolRemovedMDName != "Char" &&
                                refKeywordANDptrSymbolRemovedMDName != "UInt32" && refKeywordANDptrSymbolRemovedMDName != "Int32" && refKeywordANDptrSymbolRemovedMDName != "UInt64" &&
                                refKeywordANDptrSymbolRemovedMDName != "Int64" && refKeywordANDptrSymbolRemovedMDName != "Single" && refKeywordANDptrSymbolRemovedMDName != "Double" &&
                                refKeywordANDptrSymbolRemovedMDName != "IntPtr" && refKeywordANDptrSymbolRemovedMDName != "UIntPtr" && refKeywordANDptrSymbolRemovedMDName != "String" &&
                                refKeywordANDptrSymbolRemovedMDName != "Object" && refKeywordANDptrSymbolRemovedMDName != "Void" &&

                                ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                refKeywordRemovedMDName != "Byte[]" && refKeywordRemovedMDName != "SByte[]" && refKeywordRemovedMDName != "Boolean[]" &&
                                refKeywordRemovedMDName != "UInt16[]" && refKeywordRemovedMDName != "Int16[]" && refKeywordRemovedMDName != "Char[]" &&
                                refKeywordRemovedMDName != "UInt32[]" && refKeywordRemovedMDName != "Int32[]" && refKeywordRemovedMDName != "UInt64[]" &&
                                refKeywordRemovedMDName != "Int64[]" && refKeywordRemovedMDName != "Single[]" && refKeywordRemovedMDName != "Double[]" &&
                                refKeywordRemovedMDName != "IntPtr[]" && refKeywordRemovedMDName != "UIntPtr[]" && refKeywordRemovedMDName != "String[]" &&
                                refKeywordRemovedMDName != "Object[]" && refKeywordRemovedMDName != "Void[]" &&

                                ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                refKeywordANDptrSymbolRemovedMDName != "Byte[]" && refKeywordANDptrSymbolRemovedMDName != "SByte[]" && refKeywordANDptrSymbolRemovedMDName != "Boolean[]" &&
                                refKeywordANDptrSymbolRemovedMDName != "UInt16[]" && refKeywordANDptrSymbolRemovedMDName != "Int16[]" && refKeywordANDptrSymbolRemovedMDName != "Char[]" &&
                                refKeywordANDptrSymbolRemovedMDName != "UInt32[]" && refKeywordANDptrSymbolRemovedMDName != "Int32[]" && refKeywordANDptrSymbolRemovedMDName != "UInt64[]" &&
                                refKeywordANDptrSymbolRemovedMDName != "Int64[]" && refKeywordANDptrSymbolRemovedMDName != "Single[]" && refKeywordANDptrSymbolRemovedMDName != "Double[]" &&
                                refKeywordANDptrSymbolRemovedMDName != "IntPtr[]" && refKeywordANDptrSymbolRemovedMDName != "UIntPtr[]" && refKeywordANDptrSymbolRemovedMDName != "String[]" &&
                                refKeywordANDptrSymbolRemovedMDName != "Object[]" && refKeywordANDptrSymbolRemovedMDName != "Void[]" &&

                                ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                !string.IsNullOrEmpty(method.ReturnType.Namespace) && !string.IsNullOrWhiteSpace(method.ReturnType.Namespace))
                            {
                                retTypeName.Append(method.ReturnType.Namespace);
                                retTypeName.Append(".");
                            }
                        }

                        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                        if (refKeywordRemovedMDName == "Void")
                        {
                            retTypeName.Append("void");
                        }
                        else if (refKeywordRemovedMDName == "Byte")
                        {
                            retTypeName.Append("byte");
                        }
                        else if (refKeywordRemovedMDName == "SByte")
                        {
                            retTypeName.Append("sbyte");
                        }
                        else if (refKeywordRemovedMDName == "Boolean")
                        {
                            retTypeName.Append("bool");
                        }
                        else if (refKeywordRemovedMDName == "UInt16")
                        {
                            retTypeName.Append("ushort");
                        }
                        else if (refKeywordRemovedMDName == "Int16")
                        {
                            retTypeName.Append("short");
                        }
                        else if (refKeywordRemovedMDName == "Char")
                        {
                            retTypeName.Append("char");
                        }
                        else if (refKeywordRemovedMDName == "UInt32")
                        {
                            retTypeName.Append("uint");
                        }
                        else if (refKeywordRemovedMDName == "Int32")
                        {
                            retTypeName.Append("int");
                        }
                        else if (refKeywordRemovedMDName == "UInt64")
                        {
                            retTypeName.Append("ulong");
                        }
                        else if (refKeywordRemovedMDName == "Int64")
                        {
                            retTypeName.Append("long");
                        }
                        else if (refKeywordRemovedMDName == "Single")
                        {
                            retTypeName.Append("float");
                        }
                        else if (refKeywordRemovedMDName == "Double")
                        {
                            retTypeName.Append("double");
                        }
                        else if (refKeywordRemovedMDName == "IntPtr")
                        {
                            retTypeName.Append("IntPtr");
                        }
                        else if (refKeywordRemovedMDName == "UIntPtr")
                        {
                            retTypeName.Append("UIntPtr");
                        }
                        else if (refKeywordRemovedMDName == "String")
                        {
                            retTypeName.Append("string");
                        }
                        else if (refKeywordRemovedMDName == "Object")
                        {
                            retTypeName.Append("object");
                        }

                        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                        else if (refKeywordANDptrSymbolRemovedMDName == "Void")
                        {
                            retTypeName.Append("void*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Byte")
                        {
                            retTypeName.Append("byte*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "SByte")
                        {
                            retTypeName.Append("sbyte*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Boolean")
                        {
                            retTypeName.Append("boolean*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "UInt16")
                        {
                            retTypeName.Append("ushort*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Int16")
                        {
                            retTypeName.Append("short*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Char")
                        {
                            retTypeName.Append("char*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "UInt32")
                        {
                            retTypeName.Append("uint*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Int32")
                        {
                            retTypeName.Append("int*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "UInt64")
                        {
                            retTypeName.Append("ulong*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Int64")
                        {
                            retTypeName.Append("long*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Single")
                        {
                            retTypeName.Append("float*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Double")
                        {
                            retTypeName.Append("double*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "IntPtr")
                        {
                            retTypeName.Append("IntPtr*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "UIntPtr")
                        {
                            retTypeName.Append("UIntPtr*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "String")
                        {
                            retTypeName.Append("string*");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Object")
                        {
                            retTypeName.Append("object*");
                        }

                        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                        else if (refKeywordRemovedMDName == "Void[]")
                        {
                            retTypeName.Append("void[]");
                        }
                        else if (refKeywordRemovedMDName == "Byte[]")
                        {
                            retTypeName.Append("byte[]");
                        }
                        else if (refKeywordRemovedMDName == "SByte[]")
                        {
                            retTypeName.Append("sbyte[]");
                        }
                        else if (refKeywordRemovedMDName == "Boolean[]")
                        {
                            retTypeName.Append("boolean[]");
                        }
                        else if (refKeywordRemovedMDName == "UInt16[]")
                        {
                            retTypeName.Append("ushort[]");
                        }
                        else if (refKeywordRemovedMDName == "Int16[]")
                        {
                            retTypeName.Append("short[]");
                        }
                        else if (refKeywordRemovedMDName == "Char[]")
                        {
                            retTypeName.Append("char[]");
                        }
                        else if (refKeywordRemovedMDName == "UInt32[]")
                        {
                            retTypeName.Append("uint[]");
                        }
                        else if (refKeywordRemovedMDName == "Int32[]")
                        {
                            retTypeName.Append("int[]");
                        }
                        else if (refKeywordRemovedMDName == "UInt64[]")
                        {
                            retTypeName.Append("ulong[]");
                        }
                        else if (refKeywordRemovedMDName == "Int64[]")
                        {
                            retTypeName.Append("long[]");
                        }
                        else if (refKeywordRemovedMDName == "Single[]")
                        {
                            retTypeName.Append("float[]");
                        }
                        else if (refKeywordRemovedMDName == "Double[]")
                        {
                            retTypeName.Append("double[]");
                        }
                        else if (refKeywordRemovedMDName == "IntPtr[]")
                        {
                            retTypeName.Append("IntPtr[]");
                        }
                        else if (refKeywordRemovedMDName == "UIntPtr[]")
                        {
                            retTypeName.Append("UIntPtr[]");
                        }
                        else if (refKeywordRemovedMDName == "String[]")
                        {
                            retTypeName.Append("string[]");
                        }
                        else if (refKeywordRemovedMDName == "Object[]")
                        {
                            retTypeName.Append("object[]");
                        }

                        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                        else if (refKeywordANDptrSymbolRemovedMDName == "Void[]")
                        {
                            retTypeName.Append("void*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Byte[]")
                        {
                            retTypeName.Append("byte*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "SByte[]")
                        {
                            retTypeName.Append("sbyte*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Boolean[]")
                        {
                            retTypeName.Append("boolean*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "UInt16[]")
                        {
                            retTypeName.Append("ushort*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Int16[]")
                        {
                            retTypeName.Append("short*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Char[]")
                        {
                            retTypeName.Append("char*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "UInt32[]")
                        {
                            retTypeName.Append("uint*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Int32[]")
                        {
                            retTypeName.Append("int*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "UInt64[]")
                        {
                            retTypeName.Append("ulong*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Int64[]")
                        {
                            retTypeName.Append("long*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Single[]")
                        {
                            retTypeName.Append("float*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Double[]")
                        {
                            retTypeName.Append("double*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "IntPtr[]")
                        {
                            retTypeName.Append("IntPtr*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "UIntPtr[]")
                        {
                            retTypeName.Append("UIntPtr*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "String[]")
                        {
                            retTypeName.Append("string*[]");
                        }
                        else if (refKeywordANDptrSymbolRemovedMDName == "Object[]")
                        {
                            retTypeName.Append("object*[]");
                        }

                        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                        else
                            retTypeName.Append(refKeywordRemovedMDName);

                        retTypeName.Append(" ");
                    }
                    else if (method.ReturnType.IsPointer)
                    {
                        var ptrSymbolRemovedMDName = method.ReturnType.TypeName;

                        if (method.ReturnType.Module != mscorlib)
                        {
                            if (ptrSymbolRemovedMDName != "Byte*" && ptrSymbolRemovedMDName != "SByte*" && ptrSymbolRemovedMDName != "Boolean*" &&
                                ptrSymbolRemovedMDName != "UInt16*" && ptrSymbolRemovedMDName != "Int16*" && ptrSymbolRemovedMDName != "Char*" &&
                                ptrSymbolRemovedMDName != "UInt32*" && ptrSymbolRemovedMDName != "Int32*" && ptrSymbolRemovedMDName != "UInt64*" &&
                                ptrSymbolRemovedMDName != "Int64*" && ptrSymbolRemovedMDName != "Single*" && ptrSymbolRemovedMDName != "Double*" &&
                                ptrSymbolRemovedMDName != "IntPtr*" && ptrSymbolRemovedMDName != "UIntPtr*" && ptrSymbolRemovedMDName != "String*" &&
                                ptrSymbolRemovedMDName != "Void*" &&

                                ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                ptrSymbolRemovedMDName != "Byte*[]" && ptrSymbolRemovedMDName != "SByte*[]" && ptrSymbolRemovedMDName != "Boolean*[]" &&
                                ptrSymbolRemovedMDName != "UInt16*[]" && ptrSymbolRemovedMDName != "Int16*[]" && ptrSymbolRemovedMDName != "Char*[]" &&
                                ptrSymbolRemovedMDName != "UInt32*[]" && ptrSymbolRemovedMDName != "Int32*[]" && ptrSymbolRemovedMDName != "UInt64*[]" &&
                                ptrSymbolRemovedMDName != "Int64*[]" && ptrSymbolRemovedMDName != "Single*[]" && ptrSymbolRemovedMDName != "Double*[]" &&
                                ptrSymbolRemovedMDName != "IntPtr*[]" && ptrSymbolRemovedMDName != "UIntPtr*[]" && ptrSymbolRemovedMDName != "String*[]" &&
                                ptrSymbolRemovedMDName != "Void*[]" &&

                                ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                !string.IsNullOrEmpty(method.ReturnType.Namespace) && !string.IsNullOrWhiteSpace(method.ReturnType.Namespace))
                            {
                                retTypeName.Append(method.ReturnType.Namespace);
                                retTypeName.Append(".");
                            }
                        }

                        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                        if (ptrSymbolRemovedMDName == "Void*")
                        {
                            retTypeName.Append("void*");
                        }
                        else if (ptrSymbolRemovedMDName == "Byte*")
                        {
                            retTypeName.Append("byte*");
                        }
                        else if (ptrSymbolRemovedMDName == "SByte*")
                        {
                            retTypeName.Append("sbyte*");
                        }
                        else if (ptrSymbolRemovedMDName == "Boolean*")
                        {
                            retTypeName.Append("bool*");
                        }
                        else if (ptrSymbolRemovedMDName == "UInt16*")
                        {
                            retTypeName.Append("ushort*");
                        }
                        else if (ptrSymbolRemovedMDName == "Int16*")
                        {
                            retTypeName.Append("short*");
                        }
                        else if (ptrSymbolRemovedMDName == "Char*")
                        {
                            retTypeName.Append("char*");
                        }
                        else if (ptrSymbolRemovedMDName == "UInt32*")
                        {
                            retTypeName.Append("uint*");
                        }
                        else if (ptrSymbolRemovedMDName == "Int32*")
                        {
                            retTypeName.Append("int*");
                        }
                        else if (ptrSymbolRemovedMDName == "UInt64*")
                        {
                            retTypeName.Append("ulong*");
                        }
                        else if (ptrSymbolRemovedMDName == "Int64*")
                        {
                            retTypeName.Append("long*");
                        }
                        else if (ptrSymbolRemovedMDName == "Single*")
                        {
                            retTypeName.Append("float*");
                        }
                        else if (ptrSymbolRemovedMDName == "Double*")
                        {
                            retTypeName.Append("double*");
                        }
                        else if (ptrSymbolRemovedMDName == "IntPtr*")
                        {
                            retTypeName.Append("IntPtr*");
                        }
                        else if (ptrSymbolRemovedMDName == "UIntPtr*")
                        {
                            retTypeName.Append("UIntPtr*");
                        }
                        else if (ptrSymbolRemovedMDName == "String*")
                        {
                            retTypeName.Append("string*");
                        }
                        else if (ptrSymbolRemovedMDName == "Object*")
                        {
                            retTypeName.Append("object*");
                        }

                        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                        else if (ptrSymbolRemovedMDName == "Void*[]")
                        {
                            retTypeName.Append("void*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "Byte*[]")
                        {
                            retTypeName.Append("byte*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "SByte*[]")
                        {
                            retTypeName.Append("sbyte*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "Boolean*[]")
                        {
                            retTypeName.Append("boolean*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "UInt16*[]")
                        {
                            retTypeName.Append("ushort*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "Int16*[]")
                        {
                            retTypeName.Append("short*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "Char*[]")
                        {
                            retTypeName.Append("char*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "UInt32*[]")
                        {
                            retTypeName.Append("uint*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "Int32*[]")
                        {
                            retTypeName.Append("int*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "UInt64*[]")
                        {
                            retTypeName.Append("ulong*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "Int64*[]")
                        {
                            retTypeName.Append("long*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "Single*[]")
                        {
                            retTypeName.Append("float*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "Double*[]")
                        {
                            retTypeName.Append("double*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "IntPtr*[]")
                        {
                            retTypeName.Append("IntPtr*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "UIntPtr*[]")
                        {
                            retTypeName.Append("UIntPtr*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "String*[]")
                        {
                            retTypeName.Append("string*[]");
                        }
                        else if (ptrSymbolRemovedMDName == "Object*[]")
                        {
                            retTypeName.Append("object*[]");
                        }

                        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                        else
                            retTypeName.Append(ptrSymbolRemovedMDName);

                        retTypeName.Append(" ");
                    }
                    else
                    {
                        if (method.ReturnType.Module != mscorlib)
                        {
                            if (method.ReturnType.TypeName != "Byte" && method.ReturnType.TypeName != "SByte" && method.ReturnType.TypeName != "Boolean" &&
                                method.ReturnType.TypeName != "UInt16" && method.ReturnType.TypeName != "Int16" && method.ReturnType.TypeName != "Char" &&
                                method.ReturnType.TypeName != "UInt32" && method.ReturnType.TypeName != "Int32" && method.ReturnType.TypeName != "UInt64" &&
                                method.ReturnType.TypeName != "Int64" && method.ReturnType.TypeName != "Single" && method.ReturnType.TypeName != "Double" &&
                                method.ReturnType.TypeName != "IntPtr" && method.ReturnType.TypeName != "UIntPtr" && method.ReturnType.TypeName != "String" &&
                                method.ReturnType.TypeName != "Object" && method.ReturnType.TypeName != "Void" &&

                                ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                method.ReturnType.TypeName != "Byte[]" && method.ReturnType.TypeName != "SByte[]" && method.ReturnType.TypeName != "Boolean[]" &&
                                method.ReturnType.TypeName != "UInt16[]" && method.ReturnType.TypeName != "Int16[]" && method.ReturnType.TypeName != "Char[]" &&
                                method.ReturnType.TypeName != "UInt32[]" && method.ReturnType.TypeName != "Int32[]" && method.ReturnType.TypeName != "UInt64[]" &&
                                method.ReturnType.TypeName != "Int64[]" && method.ReturnType.TypeName != "Single[]" && method.ReturnType.TypeName != "Double[]" &&
                                method.ReturnType.TypeName != "IntPtr[]" && method.ReturnType.TypeName != "UIntPtr[]" && method.ReturnType.TypeName != "String[]" &&
                                method.ReturnType.TypeName != "Object[]" && method.ReturnType.TypeName != "Void[]" &&

                                ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                !string.IsNullOrEmpty(method.ReturnType.Namespace) && !string.IsNullOrWhiteSpace(method.ReturnType.Namespace))
                            {
                                retTypeName.Append(method.ReturnType.Namespace);
                                retTypeName.Append(".");
                            }
                        }

                        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                        if (method.ReturnType.TypeName == "Void")
                        {
                            retTypeName.Append("void");
                        }
                        else if (method.ReturnType.TypeName == "Byte")
                        {
                            retTypeName.Append("byte");
                        }
                        else if (method.ReturnType.TypeName == "SByte")
                        {
                            retTypeName.Append("sbyte");
                        }
                        else if (method.ReturnType.TypeName == "Boolean")
                        {
                            retTypeName.Append("bool");
                        }
                        else if (method.ReturnType.TypeName == "UInt16")
                        {
                            retTypeName.Append("ushort");
                        }
                        else if (method.ReturnType.TypeName == "Int16")
                        {
                            retTypeName.Append("short");
                        }
                        else if (method.ReturnType.TypeName == "Char")
                        {
                            retTypeName.Append("char");
                        }
                        else if (method.ReturnType.TypeName == "UInt32")
                        {
                            retTypeName.Append("uint");
                        }
                        else if (method.ReturnType.TypeName == "Int32")
                        {
                            retTypeName.Append("int");
                        }
                        else if (method.ReturnType.TypeName == "UInt64")
                        {
                            retTypeName.Append("ulong");
                        }
                        else if (method.ReturnType.TypeName == "Int64")
                        {
                            retTypeName.Append("long");
                        }
                        else if (method.ReturnType.TypeName == "Single")
                        {
                            retTypeName.Append("float");
                        }
                        else if (method.ReturnType.TypeName == "Double")
                        {
                            retTypeName.Append("double");
                        }
                        else if (method.ReturnType.TypeName == "IntPtr")
                        {
                            retTypeName.Append("IntPtr");
                        }
                        else if (method.ReturnType.TypeName == "UIntPtr")
                        {
                            retTypeName.Append("UIntPtr");
                        }
                        else if (method.ReturnType.TypeName == "String")
                        {
                            retTypeName.Append("string");
                        }
                        else if (method.ReturnType.TypeName == "Object")
                        {
                            retTypeName.Append("object");
                        }

                        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                        else if (method.ReturnType.TypeName == "Void[]")
                        {
                            retTypeName.Append("void[]");
                        }
                        else if (method.ReturnType.TypeName == "Byte[]")
                        {
                            retTypeName.Append("byte[]");
                        }
                        else if (method.ReturnType.TypeName == "SByte[]")
                        {
                            retTypeName.Append("sbyte[]");
                        }
                        else if (method.ReturnType.TypeName == "Boolean[]")
                        {
                            retTypeName.Append("boolean[]");
                        }
                        else if (method.ReturnType.TypeName == "UInt16[]")
                        {
                            retTypeName.Append("ushort[]");
                        }
                        else if (method.ReturnType.TypeName == "Int16[]")
                        {
                            retTypeName.Append("short[]");
                        }
                        else if (method.ReturnType.TypeName == "Char[]")
                        {
                            retTypeName.Append("char[]");
                        }
                        else if (method.ReturnType.TypeName == "UInt32[]")
                        {
                            retTypeName.Append("uint[]");
                        }
                        else if (method.ReturnType.TypeName == "Int32[]")
                        {
                            retTypeName.Append("int[]");
                        }
                        else if (method.ReturnType.TypeName == "UInt64[]")
                        {
                            retTypeName.Append("ulong[]");
                        }
                        else if (method.ReturnType.TypeName == "Int64[]")
                        {
                            retTypeName.Append("long[]");
                        }
                        else if (method.ReturnType.TypeName == "Single[]")
                        {
                            retTypeName.Append("float[]");
                        }
                        else if (method.ReturnType.TypeName == "Double[]")
                        {
                            retTypeName.Append("double[]");
                        }
                        else if (method.ReturnType.TypeName == "IntPtr[]")
                        {
                            retTypeName.Append("IntPtr[]");
                        }
                        else if (method.ReturnType.TypeName == "UIntPtr[]")
                        {
                            retTypeName.Append("UIntPtr[]");
                        }
                        else if (method.ReturnType.TypeName == "String[]")
                        {
                            retTypeName.Append("string[]");
                        }
                        else if (method.ReturnType.TypeName == "Object[]")
                        {
                            retTypeName.Append("object[]");
                        }

                        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                        else
                            retTypeName.Append(method.ReturnType.TypeName);

                        retTypeName.Append(" ");
                    }
                    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                    #endregion

                    mdFullName += retTypeName.ToString();

                    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                    if (method.IsConstructor || method.IsStaticConstructor || method.IsInstanceConstructor || method.IsInternalCall)
                        mdFullName += type.Name;
                    else
                        mdFullName += $"{ type.FullName }.{ method.Name }";

                    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                    mdFullName += "(";

                    var paramTypeName = new StringBuilder();
                    for (int i = 1; i < method.Parameters.Count; i++)
                    {
                        var param = method.Parameters[i];

                        #region Read Parameter Type Namespace and Name
                        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                        if (param.Type.IsByRef)
                        {
                            var refKeywordRemovedPMName = param.Type.TypeName.Substring(0, param.Type.TypeName.Length - 1);
                            var refKeywordANDptrSymbolRemovedPMName = refKeywordRemovedPMName.Substring(0, refKeywordRemovedPMName.Length - 1);

                            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                            paramTypeName.Append("ref ");

                            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                            if (param.Type.Module != mscorlib)
                            {
                                if (refKeywordRemovedPMName != "Byte" && refKeywordRemovedPMName != "SByte" && refKeywordRemovedPMName != "Boolean" &&
                                    refKeywordRemovedPMName != "UInt16" && refKeywordRemovedPMName != "Int16" && refKeywordRemovedPMName != "Char" &&
                                    refKeywordRemovedPMName != "UInt32" && refKeywordRemovedPMName != "Int32" && refKeywordRemovedPMName != "UInt64" &&
                                    refKeywordRemovedPMName != "Int64" && refKeywordRemovedPMName != "Single" && refKeywordRemovedPMName != "Double" &&
                                    refKeywordRemovedPMName != "IntPtr" && refKeywordRemovedPMName != "UIntPtr" && refKeywordRemovedPMName != "String" &&
                                    refKeywordRemovedPMName != "Object" && refKeywordRemovedPMName != "Void" &&

                                    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                    refKeywordANDptrSymbolRemovedPMName != "Byte" && refKeywordANDptrSymbolRemovedPMName != "SByte" && refKeywordANDptrSymbolRemovedPMName != "Boolean" &&
                                    refKeywordANDptrSymbolRemovedPMName != "UInt16" && refKeywordANDptrSymbolRemovedPMName != "Int16" && refKeywordANDptrSymbolRemovedPMName != "Char" &&
                                    refKeywordANDptrSymbolRemovedPMName != "UInt32" && refKeywordANDptrSymbolRemovedPMName != "Int32" && refKeywordANDptrSymbolRemovedPMName != "UInt64" &&
                                    refKeywordANDptrSymbolRemovedPMName != "Int64" && refKeywordANDptrSymbolRemovedPMName != "Single" && refKeywordANDptrSymbolRemovedPMName != "Double" &&
                                    refKeywordANDptrSymbolRemovedPMName != "IntPtr" && refKeywordANDptrSymbolRemovedPMName != "UIntPtr" && refKeywordANDptrSymbolRemovedPMName != "String" &&
                                    refKeywordANDptrSymbolRemovedPMName != "Object" && refKeywordANDptrSymbolRemovedPMName != "Void" &&

                                    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                    refKeywordRemovedPMName != "Byte[]" && refKeywordRemovedPMName != "SByte[]" && refKeywordRemovedPMName != "Boolean[]" &&
                                    refKeywordRemovedPMName != "UInt16[]" && refKeywordRemovedPMName != "Int16[]" && refKeywordRemovedPMName != "Char[]" &&
                                    refKeywordRemovedPMName != "UInt32[]" && refKeywordRemovedPMName != "Int32[]" && refKeywordRemovedPMName != "UInt64[]" &&
                                    refKeywordRemovedPMName != "Int64[]" && refKeywordRemovedPMName != "Single[]" && refKeywordRemovedPMName != "Double[]" &&
                                    refKeywordRemovedPMName != "IntPtr[]" && refKeywordRemovedPMName != "UIntPtr[]" && refKeywordRemovedPMName != "String[]" &&
                                    refKeywordRemovedPMName != "Object[]" && refKeywordRemovedPMName != "Void[]" &&

                                    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                    refKeywordANDptrSymbolRemovedPMName != "Byte[]" && refKeywordANDptrSymbolRemovedPMName != "SByte[]" && refKeywordANDptrSymbolRemovedPMName != "Boolean[]" &&
                                    refKeywordANDptrSymbolRemovedPMName != "UInt16[]" && refKeywordANDptrSymbolRemovedPMName != "Int16[]" && refKeywordANDptrSymbolRemovedPMName != "Char[]" &&
                                    refKeywordANDptrSymbolRemovedPMName != "UInt32[]" && refKeywordANDptrSymbolRemovedPMName != "Int32[]" && refKeywordANDptrSymbolRemovedPMName != "UInt64[]" &&
                                    refKeywordANDptrSymbolRemovedPMName != "Int64[]" && refKeywordANDptrSymbolRemovedPMName != "Single[]" && refKeywordANDptrSymbolRemovedPMName != "Double[]" &&
                                    refKeywordANDptrSymbolRemovedPMName != "IntPtr[]" && refKeywordANDptrSymbolRemovedPMName != "UIntPtr[]" && refKeywordANDptrSymbolRemovedPMName != "String[]" &&
                                    refKeywordANDptrSymbolRemovedPMName != "Object[]" && refKeywordANDptrSymbolRemovedPMName != "Void[]" &&

                                    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                    !string.IsNullOrEmpty(param.Type.Namespace) && !string.IsNullOrWhiteSpace(param.Type.Namespace))
                                {
                                    paramTypeName.Append(param.Type.Namespace);
                                    paramTypeName.Append(".");
                                }
                            }

                            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                            if (refKeywordRemovedPMName == "Void")
                            {
                                paramTypeName.Append("void");
                            }
                            else if (refKeywordRemovedPMName == "Byte")
                            {
                                paramTypeName.Append("byte");
                            }
                            else if (refKeywordRemovedPMName == "SByte")
                            {
                                paramTypeName.Append("sbyte");
                            }
                            else if (refKeywordRemovedPMName == "Boolean")
                            {
                                paramTypeName.Append("bool");
                            }
                            else if (refKeywordRemovedPMName == "UInt16")
                            {
                                paramTypeName.Append("ushort");
                            }
                            else if (refKeywordRemovedPMName == "Int16")
                            {
                                paramTypeName.Append("short");
                            }
                            else if (refKeywordRemovedPMName == "Char")
                            {
                                paramTypeName.Append("char");
                            }
                            else if (refKeywordRemovedPMName == "UInt32")
                            {
                                paramTypeName.Append("uint");
                            }
                            else if (refKeywordRemovedPMName == "Int32")
                            {
                                paramTypeName.Append("int");
                            }
                            else if (refKeywordRemovedPMName == "UInt64")
                            {
                                paramTypeName.Append("ulong");
                            }
                            else if (refKeywordRemovedPMName == "Int64")
                            {
                                paramTypeName.Append("long");
                            }
                            else if (refKeywordRemovedPMName == "Single")
                            {
                                paramTypeName.Append("float");
                            }
                            else if (refKeywordRemovedPMName == "Double")
                            {
                                paramTypeName.Append("double");
                            }
                            else if (refKeywordRemovedPMName == "IntPtr")
                            {
                                paramTypeName.Append("IntPtr");
                            }
                            else if (refKeywordRemovedPMName == "UIntPtr")
                            {
                                paramTypeName.Append("UIntPtr");
                            }
                            else if (refKeywordRemovedPMName == "String")
                            {
                                paramTypeName.Append("string");
                            }
                            else if (refKeywordRemovedPMName == "Object")
                            {
                                paramTypeName.Append("object");
                            }

                            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                            else if (refKeywordANDptrSymbolRemovedPMName == "Void")
                            {
                                paramTypeName.Append("void*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Byte")
                            {
                                paramTypeName.Append("byte*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "SByte")
                            {
                                paramTypeName.Append("sbyte*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Boolean")
                            {
                                paramTypeName.Append("boolean*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "UInt16")
                            {
                                paramTypeName.Append("ushort*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Int16")
                            {
                                paramTypeName.Append("short*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Char")
                            {
                                paramTypeName.Append("char*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "UInt32")
                            {
                                paramTypeName.Append("uint*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Int32")
                            {
                                paramTypeName.Append("int*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "UInt64")
                            {
                                paramTypeName.Append("ulong*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Int64")
                            {
                                paramTypeName.Append("long*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Single")
                            {
                                paramTypeName.Append("float*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Double")
                            {
                                paramTypeName.Append("double*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "IntPtr")
                            {
                                paramTypeName.Append("IntPtr*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "UIntPtr")
                            {
                                paramTypeName.Append("UIntPtr*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "String")
                            {
                                paramTypeName.Append("string*");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Object")
                            {
                                paramTypeName.Append("object*");
                            }

                            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                            else if (refKeywordRemovedPMName == "Void[]")
                            {
                                paramTypeName.Append("void[]");
                            }
                            else if (refKeywordRemovedPMName == "Byte[]")
                            {
                                paramTypeName.Append("byte[]");
                            }
                            else if (refKeywordRemovedPMName == "SByte[]")
                            {
                                paramTypeName.Append("sbyte[]");
                            }
                            else if (refKeywordRemovedPMName == "Boolean[]")
                            {
                                paramTypeName.Append("boolean[]");
                            }
                            else if (refKeywordRemovedPMName == "UInt16[]")
                            {
                                paramTypeName.Append("ushort[]");
                            }
                            else if (refKeywordRemovedPMName == "Int16[]")
                            {
                                paramTypeName.Append("short[]");
                            }
                            else if (refKeywordRemovedPMName == "Char[]")
                            {
                                paramTypeName.Append("char[]");
                            }
                            else if (refKeywordRemovedPMName == "UInt32[]")
                            {
                                paramTypeName.Append("uint[]");
                            }
                            else if (refKeywordRemovedPMName == "Int32[]")
                            {
                                paramTypeName.Append("int[]");
                            }
                            else if (refKeywordRemovedPMName == "UInt64[]")
                            {
                                paramTypeName.Append("ulong[]");
                            }
                            else if (refKeywordRemovedPMName == "Int64[]")
                            {
                                paramTypeName.Append("long[]");
                            }
                            else if (refKeywordRemovedPMName == "Single[]")
                            {
                                paramTypeName.Append("float[]");
                            }
                            else if (refKeywordRemovedPMName == "Double[]")
                            {
                                paramTypeName.Append("double[]");
                            }
                            else if (refKeywordRemovedPMName == "IntPtr[]")
                            {
                                paramTypeName.Append("IntPtr[]");
                            }
                            else if (refKeywordRemovedPMName == "UIntPtr[]")
                            {
                                paramTypeName.Append("UIntPtr[]");
                            }
                            else if (refKeywordRemovedPMName == "String[]")
                            {
                                paramTypeName.Append("string[]");
                            }
                            else if (refKeywordRemovedPMName == "Object[]")
                            {
                                paramTypeName.Append("object[]");
                            }

                            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                            else if (refKeywordANDptrSymbolRemovedPMName == "Void[]")
                            {
                                paramTypeName.Append("void*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Byte[]")
                            {
                                paramTypeName.Append("byte*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "SByte[]")
                            {
                                paramTypeName.Append("sbyte*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Boolean[]")
                            {
                                paramTypeName.Append("boolean*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "UInt16[]")
                            {
                                paramTypeName.Append("ushort*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Int16[]")
                            {
                                paramTypeName.Append("short*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Char[]")
                            {
                                paramTypeName.Append("char*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "UInt32[]")
                            {
                                paramTypeName.Append("uint*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Int32[]")
                            {
                                paramTypeName.Append("int*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "UInt64[]")
                            {
                                paramTypeName.Append("ulong*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Int64[]")
                            {
                                paramTypeName.Append("long*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Single[]")
                            {
                                paramTypeName.Append("float*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Double[]")
                            {
                                paramTypeName.Append("double*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "IntPtr[]")
                            {
                                paramTypeName.Append("IntPtr*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "UIntPtr[]")
                            {
                                paramTypeName.Append("UIntPtr*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "String[]")
                            {
                                paramTypeName.Append("string*[]");
                            }
                            else if (refKeywordANDptrSymbolRemovedPMName == "Object[]")
                            {
                                paramTypeName.Append("object*[]");
                            }

                            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                            else
                                paramTypeName.Append(refKeywordRemovedPMName);
                        }
                        else if (param.Type.IsPointer)
                        {
                            var ptrSymbolRemovedPMName = param.Type.TypeName;

                            if (param.Type.Module != mscorlib)
                            {
                                if (ptrSymbolRemovedPMName != "Byte*" && ptrSymbolRemovedPMName != "SByte*" && ptrSymbolRemovedPMName != "Boolean*" &&
                                    ptrSymbolRemovedPMName != "UInt16*" && ptrSymbolRemovedPMName != "Int16*" && ptrSymbolRemovedPMName != "Char*" &&
                                    ptrSymbolRemovedPMName != "UInt32*" && ptrSymbolRemovedPMName != "Int32*" && ptrSymbolRemovedPMName != "UInt64*" &&
                                    ptrSymbolRemovedPMName != "Int64*" && ptrSymbolRemovedPMName != "Single*" && ptrSymbolRemovedPMName != "Double*" &&
                                    ptrSymbolRemovedPMName != "IntPtr*" && ptrSymbolRemovedPMName != "UIntPtr*" && ptrSymbolRemovedPMName != "String*" &&
                                    ptrSymbolRemovedPMName != "Void*" &&

                                    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                    ptrSymbolRemovedPMName != "Byte*[]" && ptrSymbolRemovedPMName != "SByte*[]" && ptrSymbolRemovedPMName != "Boolean*[]" &&
                                    ptrSymbolRemovedPMName != "UInt16*[]" && ptrSymbolRemovedPMName != "Int16*[]" && ptrSymbolRemovedPMName != "Char*[]" &&
                                    ptrSymbolRemovedPMName != "UInt32*[]" && ptrSymbolRemovedPMName != "Int32*[]" && ptrSymbolRemovedPMName != "UInt64*[]" &&
                                    ptrSymbolRemovedPMName != "Int64*[]" && ptrSymbolRemovedPMName != "Single*[]" && ptrSymbolRemovedPMName != "Double*[]" &&
                                    ptrSymbolRemovedPMName != "IntPtr*[]" && ptrSymbolRemovedPMName != "UIntPtr*[]" && ptrSymbolRemovedPMName != "String*[]" &&
                                    ptrSymbolRemovedPMName != "Void*[]" &&

                                    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                    !string.IsNullOrEmpty(param.Type.Namespace) && !string.IsNullOrWhiteSpace(param.Type.Namespace))
                                {
                                    paramTypeName.Append(param.Type.Namespace);
                                    paramTypeName.Append(".");
                                }
                            }

                            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                            if (ptrSymbolRemovedPMName == "Void*")
                            {
                                paramTypeName.Append("void*");
                            }
                            else if (ptrSymbolRemovedPMName == "Byte*")
                            {
                                paramTypeName.Append("byte*");
                            }
                            else if (ptrSymbolRemovedPMName == "SByte*")
                            {
                                paramTypeName.Append("sbyte*");
                            }
                            else if (ptrSymbolRemovedPMName == "Boolean*")
                            {
                                paramTypeName.Append("bool*");
                            }
                            else if (ptrSymbolRemovedPMName == "UInt16*")
                            {
                                paramTypeName.Append("ushort*");
                            }
                            else if (ptrSymbolRemovedPMName == "Int16*")
                            {
                                paramTypeName.Append("short*");
                            }
                            else if (ptrSymbolRemovedPMName == "Char*")
                            {
                                paramTypeName.Append("char*");
                            }
                            else if (ptrSymbolRemovedPMName == "UInt32*")
                            {
                                paramTypeName.Append("uint*");
                            }
                            else if (ptrSymbolRemovedPMName == "Int32*")
                            {
                                paramTypeName.Append("int*");
                            }
                            else if (ptrSymbolRemovedPMName == "UInt64*")
                            {
                                paramTypeName.Append("ulong*");
                            }
                            else if (ptrSymbolRemovedPMName == "Int64*")
                            {
                                paramTypeName.Append("long*");
                            }
                            else if (ptrSymbolRemovedPMName == "Single*")
                            {
                                paramTypeName.Append("float*");
                            }
                            else if (ptrSymbolRemovedPMName == "Double*")
                            {
                                paramTypeName.Append("double*");
                            }
                            else if (ptrSymbolRemovedPMName == "IntPtr*")
                            {
                                paramTypeName.Append("IntPtr*");
                            }
                            else if (ptrSymbolRemovedPMName == "UIntPtr*")
                            {
                                paramTypeName.Append("UIntPtr*");
                            }
                            else if (ptrSymbolRemovedPMName == "String*")
                            {
                                paramTypeName.Append("string*");
                            }
                            else if (ptrSymbolRemovedPMName == "Object*")
                            {
                                paramTypeName.Append("object*");
                            }

                            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                            else if (ptrSymbolRemovedPMName == "Void*[]")
                            {
                                paramTypeName.Append("void*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "Byte*[]")
                            {
                                paramTypeName.Append("byte*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "SByte*[]")
                            {
                                paramTypeName.Append("sbyte*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "Boolean*[]")
                            {
                                paramTypeName.Append("boolean*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "UInt16*[]")
                            {
                                paramTypeName.Append("ushort*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "Int16*[]")
                            {
                                paramTypeName.Append("short*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "Char*[]")
                            {
                                paramTypeName.Append("char*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "UInt32*[]")
                            {
                                paramTypeName.Append("uint*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "Int32*[]")
                            {
                                paramTypeName.Append("int*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "UInt64*[]")
                            {
                                paramTypeName.Append("ulong*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "Int64*[]")
                            {
                                paramTypeName.Append("long*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "Single*[]")
                            {
                                paramTypeName.Append("float*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "Double*[]")
                            {
                                paramTypeName.Append("double*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "IntPtr*[]")
                            {
                                paramTypeName.Append("IntPtr*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "UIntPtr*[]")
                            {
                                paramTypeName.Append("UIntPtr*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "String*[]")
                            {
                                paramTypeName.Append("string*[]");
                            }
                            else if (ptrSymbolRemovedPMName == "Object*[]")
                            {
                                paramTypeName.Append("object*[]");
                            }

                            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                            else
                                paramTypeName.Append(ptrSymbolRemovedPMName);
                        }
                        else
                        {
                            if (param.Type.Module != mscorlib)
                            {
                                if (param.Type.TypeName != "Byte" && param.Type.TypeName != "SByte" && param.Type.TypeName != "Boolean" &&
                                    param.Type.TypeName != "UInt16" && param.Type.TypeName != "Int16" && param.Type.TypeName != "Char" &&
                                    param.Type.TypeName != "UInt32" && param.Type.TypeName != "Int32" && param.Type.TypeName != "UInt64" &&
                                    param.Type.TypeName != "Int64" && param.Type.TypeName != "Single" && param.Type.TypeName != "Double" &&
                                    param.Type.TypeName != "IntPtr" && param.Type.TypeName != "UIntPtr" && param.Type.TypeName != "String" &&
                                    param.Type.TypeName != "Object" && param.Type.TypeName != "Void" &&

                                    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                    param.Type.TypeName != "Byte[]" && param.Type.TypeName != "SByte[]" && param.Type.TypeName != "Boolean[]" &&
                                    param.Type.TypeName != "UInt16[]" && param.Type.TypeName != "Int16[]" && param.Type.TypeName != "Char[]" &&
                                    param.Type.TypeName != "UInt32[]" && param.Type.TypeName != "Int32[]" && param.Type.TypeName != "UInt64[]" &&
                                    param.Type.TypeName != "Int64[]" && param.Type.TypeName != "Single[]" && param.Type.TypeName != "Double[]" &&
                                    param.Type.TypeName != "IntPtr[]" && param.Type.TypeName != "UIntPtr[]" && param.Type.TypeName != "String[]" &&
                                    param.Type.TypeName != "Object[]" && param.Type.TypeName != "Void[]" &&

                                    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                                    !string.IsNullOrEmpty(param.Type.Namespace) && !string.IsNullOrWhiteSpace(param.Type.Namespace))
                                {
                                    paramTypeName.Append(param.Type.Namespace);
                                    paramTypeName.Append(".");
                                }
                            }

                            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                            if (param.Type.TypeName == "Void")
                            {
                                paramTypeName.Append("void");
                            }
                            else if (param.Type.TypeName == "Byte")
                            {
                                paramTypeName.Append("byte");
                            }
                            else if (param.Type.TypeName == "SByte")
                            {
                                paramTypeName.Append("sbyte");
                            }
                            else if (param.Type.TypeName == "Boolean")
                            {
                                paramTypeName.Append("bool");
                            }
                            else if (param.Type.TypeName == "UInt16")
                            {
                                paramTypeName.Append("ushort");
                            }
                            else if (param.Type.TypeName == "Int16")
                            {
                                paramTypeName.Append("short");
                            }
                            else if (param.Type.TypeName == "Char")
                            {
                                paramTypeName.Append("char");
                            }
                            else if (param.Type.TypeName == "UInt32")
                            {
                                paramTypeName.Append("uint");
                            }
                            else if (param.Type.TypeName == "Int32")
                            {
                                paramTypeName.Append("int");
                            }
                            else if (param.Type.TypeName == "UInt64")
                            {
                                paramTypeName.Append("ulong");
                            }
                            else if (param.Type.TypeName == "Int64")
                            {
                                paramTypeName.Append("long");
                            }
                            else if (param.Type.TypeName == "Single")
                            {
                                paramTypeName.Append("float");
                            }
                            else if (param.Type.TypeName == "Double")
                            {
                                paramTypeName.Append("double");
                            }
                            else if (param.Type.TypeName == "IntPtr")
                            {
                                paramTypeName.Append("IntPtr");
                            }
                            else if (param.Type.TypeName == "UIntPtr")
                            {
                                paramTypeName.Append("UIntPtr");
                            }
                            else if (param.Type.TypeName == "String")
                            {
                                paramTypeName.Append("string");
                            }
                            else if (param.Type.TypeName == "Object")
                            {
                                paramTypeName.Append("object");
                            }

                            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                            else if (param.Type.TypeName == "Void[]")
                            {
                                paramTypeName.Append("void[]");
                            }
                            else if (param.Type.TypeName == "Byte[]")
                            {
                                paramTypeName.Append("byte[]");
                            }
                            else if (param.Type.TypeName == "SByte[]")
                            {
                                paramTypeName.Append("sbyte[]");
                            }
                            else if (param.Type.TypeName == "Boolean[]")
                            {
                                paramTypeName.Append("boolean[]");
                            }
                            else if (param.Type.TypeName == "UInt16[]")
                            {
                                paramTypeName.Append("ushort[]");
                            }
                            else if (param.Type.TypeName == "Int16[]")
                            {
                                paramTypeName.Append("short[]");
                            }
                            else if (param.Type.TypeName == "Char[]")
                            {
                                paramTypeName.Append("char[]");
                            }
                            else if (param.Type.TypeName == "UInt32[]")
                            {
                                paramTypeName.Append("uint[]");
                            }
                            else if (param.Type.TypeName == "Int32[]")
                            {
                                paramTypeName.Append("int[]");
                            }
                            else if (param.Type.TypeName == "UInt64[]")
                            {
                                paramTypeName.Append("ulong[]");
                            }
                            else if (param.Type.TypeName == "Int64[]")
                            {
                                paramTypeName.Append("long[]");
                            }
                            else if (param.Type.TypeName == "Single[]")
                            {
                                paramTypeName.Append("float[]");
                            }
                            else if (param.Type.TypeName == "Double[]")
                            {
                                paramTypeName.Append("double[]");
                            }
                            else if (param.Type.TypeName == "IntPtr[]")
                            {
                                paramTypeName.Append("IntPtr[]");
                            }
                            else if (param.Type.TypeName == "UIntPtr[]")
                            {
                                paramTypeName.Append("UIntPtr[]");
                            }
                            else if (param.Type.TypeName == "String[]")
                            {
                                paramTypeName.Append("string[]");
                            }
                            else if (param.Type.TypeName == "Object[]")
                            {
                                paramTypeName.Append("object[]");
                            }

                            ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                            else
                                paramTypeName.Append(param.Type.TypeName);
                        }
                        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                        #endregion

                        if (!string.IsNullOrEmpty(param.Name) && !string.IsNullOrWhiteSpace(param.Name))
                            paramTypeName.Append($" { param.Name }, ");
                        else
                            paramTypeName.Append($" arg{i}, ");
                    }

                    mdFullName += paramTypeName.ToString();

                    if (method.Parameters.Count != 0 && method.Parameters.Count != 1)
                        mdFullName = mdFullName.Substring(0, mdFullName.Length - 2) + ");";
                    else
                        mdFullName += ");";

                    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

                    var item = new CheckedListBoxItem(mdFullName);
                    item.Tag = method;

                    if (VirtualizeAllFunctionsToggle.IsOn)
                        item.CheckState = CheckState.Checked;
                    else
                        item.CheckState = CheckState.Unchecked;

                    FunctionsCheckList.Items.Add(item);
                    TempMethodList.Add(item);

                    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                }
            }

            // Research
            if (FunctionSearchBox.Text != "Search method name..." && FunctionSearchBox.Text != " Search method name...")
                FunctionSearchBox_TextChanged(null, null);
        }

        #region Show Page Buttons "CheckedChanged" Events
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        private void ShowMainPageCheckButton_CheckedChanged(object sender, EventArgs e)
        {
            if (ShowMainPageCheckButton.Checked)
            {
                EXGTabControl.SelectedTabPage = MainTabPage;

                ShowMainPageCheckButton.Font = new Font(this.Font, FontStyle.Bold);

                ShowProtectionsPageCheckButton.Font = this.Font;
                ShowFunctionsPageCheckButton.Font = this.Font;
                ShowRuntimeSettingsPageCheckButton.Font = this.Font;
                ShowLogsPageAndProtectCheckButton.Font = this.Font;
                ShowAboutPageCheckButton.Font = this.Font;

                ShowProtectionsPageCheckButton.Checked = false;
                ShowFunctionsPageCheckButton.Checked = false;
                ShowRuntimeSettingsPageCheckButton.Checked = false;
                ShowLogsPageAndProtectCheckButton.Checked = false;
                ShowAboutPageCheckButton.Checked = false;
            }
            else if (!ShowProtectionsPageCheckButton.Checked && !ShowFunctionsPageCheckButton.Checked && !ShowRuntimeSettingsPageCheckButton.Checked && !ShowLogsPageAndProtectCheckButton.Checked && !ShowAboutPageCheckButton.Checked)
                ShowMainPageCheckButton.Checked = true;
        }

        private void ShowProtectionsPageCheckButton_CheckedChanged(object sender, EventArgs e)
        {
            if (ShowProtectionsPageCheckButton.Checked)
            {
                EXGTabControl.SelectedTabPage = ProtectionsTabPage;

                ShowProtectionsPageCheckButton.Font = new Font(this.Font, FontStyle.Bold);

                ShowMainPageCheckButton.Font = this.Font;
                ShowFunctionsPageCheckButton.Font = this.Font;
                ShowRuntimeSettingsPageCheckButton.Font = this.Font;
                ShowLogsPageAndProtectCheckButton.Font = this.Font;
                ShowAboutPageCheckButton.Font = this.Font;

                ShowMainPageCheckButton.Checked = false;
                ShowFunctionsPageCheckButton.Checked = false;
                ShowRuntimeSettingsPageCheckButton.Checked = false;
                ShowLogsPageAndProtectCheckButton.Checked = false;
                ShowAboutPageCheckButton.Checked = false;
            }
            else if (!ShowMainPageCheckButton.Checked && !ShowFunctionsPageCheckButton.Checked && !ShowRuntimeSettingsPageCheckButton.Checked && !ShowLogsPageAndProtectCheckButton.Checked && !ShowAboutPageCheckButton.Checked)
                ShowProtectionsPageCheckButton.Checked = true;
        }

        private void ShowFunctionsPageCheckButton_CheckedChanged(object sender, EventArgs e)
        {
            if (ShowFunctionsPageCheckButton.Checked)
            {
                EXGTabControl.SelectedTabPage = FunctionsTabPage;

                ShowFunctionsPageCheckButton.Font = new Font(this.Font, FontStyle.Bold);

                ShowMainPageCheckButton.Font = this.Font;
                ShowProtectionsPageCheckButton.Font = this.Font;
                ShowRuntimeSettingsPageCheckButton.Font = this.Font;
                ShowLogsPageAndProtectCheckButton.Font = this.Font;
                ShowAboutPageCheckButton.Font = this.Font;

                ShowMainPageCheckButton.Checked = false;
                ShowProtectionsPageCheckButton.Checked = false;
                ShowRuntimeSettingsPageCheckButton.Checked = false;
                ShowLogsPageAndProtectCheckButton.Checked = false;
                ShowAboutPageCheckButton.Checked = false;
            }
            else if (!ShowMainPageCheckButton.Checked && !ShowProtectionsPageCheckButton.Checked && !ShowRuntimeSettingsPageCheckButton.Checked && !ShowLogsPageAndProtectCheckButton.Checked && !ShowAboutPageCheckButton.Checked)
                ShowFunctionsPageCheckButton.Checked = true;
        }

        private void ShowRuntimeSettingsPageCheckButton_CheckedChanged(object sender, EventArgs e)
        {
            if (ShowRuntimeSettingsPageCheckButton.Checked)
            {
                EXGTabControl.SelectedTabPage = RuntimeSettingsTabPage;

                ShowRuntimeSettingsPageCheckButton.Font = new Font(this.Font, FontStyle.Bold);

                ShowMainPageCheckButton.Font = this.Font;
                ShowProtectionsPageCheckButton.Font = this.Font;
                ShowFunctionsPageCheckButton.Font = this.Font;
                ShowLogsPageAndProtectCheckButton.Font = this.Font;
                ShowAboutPageCheckButton.Font = this.Font;

                ShowMainPageCheckButton.Checked = false;
                ShowProtectionsPageCheckButton.Checked = false;
                ShowFunctionsPageCheckButton.Checked = false;
                ShowLogsPageAndProtectCheckButton.Checked = false;
                ShowAboutPageCheckButton.Checked = false;
            }
            else if (!ShowMainPageCheckButton.Checked && !ShowProtectionsPageCheckButton.Checked && !ShowFunctionsPageCheckButton.Checked && !ShowLogsPageAndProtectCheckButton.Checked && !ShowAboutPageCheckButton.Checked)
                ShowRuntimeSettingsPageCheckButton.Checked = true;
        }

        private void ShowLogsPageCheckButton_CheckedChanged(object sender, EventArgs e)
        {
            if (ShowLogsPageAndProtectCheckButton.Checked)
            {
                EXGTabControl.SelectedTabPage = LogsTabPage;

                ShowLogsPageAndProtectCheckButton.Font = new Font(this.Font, FontStyle.Bold);

                ShowMainPageCheckButton.Font = this.Font;
                ShowProtectionsPageCheckButton.Font = this.Font;
                ShowFunctionsPageCheckButton.Font = this.Font;
                ShowRuntimeSettingsPageCheckButton.Font = this.Font;
                ShowAboutPageCheckButton.Font = this.Font;

                ShowMainPageCheckButton.Checked = false;
                ShowProtectionsPageCheckButton.Checked = false;
                ShowFunctionsPageCheckButton.Checked = false;
                ShowRuntimeSettingsPageCheckButton.Checked = false;
                ShowAboutPageCheckButton.Checked = false;
            }
            else if (!ShowMainPageCheckButton.Checked && !ShowProtectionsPageCheckButton.Checked && !ShowFunctionsPageCheckButton.Checked && !ShowRuntimeSettingsPageCheckButton.Checked && !ShowAboutPageCheckButton.Checked)
                ShowLogsPageAndProtectCheckButton.Checked = true;
        }

        private void ShowAboutPageCheckButton_CheckedChanged(object sender, EventArgs e)
        {
            if (ShowAboutPageCheckButton.Checked)
            {
                EXGTabControl.SelectedTabPage = AboutTabPage;

                ShowAboutPageCheckButton.Font = new Font(this.Font, FontStyle.Bold);

                ShowMainPageCheckButton.Font = this.Font;
                ShowProtectionsPageCheckButton.Font = this.Font;
                ShowFunctionsPageCheckButton.Font = this.Font;
                ShowRuntimeSettingsPageCheckButton.Font = this.Font;
                ShowLogsPageAndProtectCheckButton.Font = this.Font;

                ShowMainPageCheckButton.Checked = false;
                ShowProtectionsPageCheckButton.Checked = false;
                ShowFunctionsPageCheckButton.Checked = false;
                ShowRuntimeSettingsPageCheckButton.Checked = false;
                ShowLogsPageAndProtectCheckButton.Checked = false;
            }
            else if (!ShowMainPageCheckButton.Checked && !ShowProtectionsPageCheckButton.Checked && !ShowFunctionsPageCheckButton.Checked && !ShowRuntimeSettingsPageCheckButton.Checked && !ShowLogsPageAndProtectCheckButton.Checked)
                ShowAboutPageCheckButton.Checked = true;
        }
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        #endregion

        #region Show Page Buttons (Click) Events
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        private void ShowMainPageCheckButton_Click(object sender, EventArgs e)
        {
            
        }

        private void ShowProtectionsPageCheckButton_Click(object sender, EventArgs e)
        {
            
        }

        private void ShowFunctionsPageCheckButton_Click(object sender, EventArgs e)
        {
            
        }

        private void ShowRuntimeSettingsPageCheckButton_Click(object sender, EventArgs e)
        {
            
        }

        private void ShowLogsPageAndProtectCheckButton_Click(object sender, EventArgs e)
        {
            Protect(this);
        }

        private void ShowAboutPageCheckButton_Click(object sender, EventArgs e)
        {

        }
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        #endregion

        #region Main Page
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        #region Assembly Group Events
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        private void BrowseAsmButton_Click(object sender, EventArgs e)
        {
            OpenFileDialog AsmOFD = new OpenFileDialog();
            AsmOFD.FileName = string.Empty;
            AsmOFD.Title = "Choose assembly to protect";
            AsmOFD.Filter = "Assembly File(*.exe, *.dll)|*.exe;*.dll|All files(*.*)|*.*";
            AsmOFD.CheckFileExists = true;

            if (AsmOFD.ShowDialog() == DialogResult.OK)
            {
                string fileLocation = AsmOFD.FileName;
                if (fileLocation.Length > 0 && Utils.IsDotNetAssembly(fileLocation))
                {
                    ResetSettings();

                    AsmBox.Text = fileLocation;
                    EXECModule = ModuleDefMD.Load(fileLocation);

                    AddMethodsToFunctionsCheckList();

                    if (!string.IsNullOrEmpty(DestinationBox.Text))
                        ShowLogsPageAndProtectCheckButton.Enabled = true;
                }
                else
                    MessageBox.Show("Your file is not .NET based!", "ERROR!", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void AsmBox_DragDrop(object sender, DragEventArgs e)
        {
            object data = e.Data.GetData(DataFormats.FileDrop);
            if (data != null)
            {
                string[] array = data as string[];
                if (array.Length == 1)
                {
                    string fileLocation = array[0];
                    if (Utils.IsDotNetAssembly(fileLocation))
                    {
                        ResetSettings();

                        AsmBox.Text = fileLocation;
                        EXECModule = ModuleDefMD.Load(fileLocation);

                        AddMethodsToFunctionsCheckList();

                        if (!string.IsNullOrEmpty(DestinationBox.Text))
                            ShowLogsPageAndProtectCheckButton.Enabled = true;
                    }
                    else
                        MessageBox.Show("Your file is not .NET based!", "ERROR!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        #endregion

        #region Destination Group Events
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        private void BrowseDestinationButton_Click(object sender, EventArgs e)
        {
            SaveFileDialog DestSFD = new SaveFileDialog();

            if (AsmBox.Text != string.Empty && AsmBox.Text != "" && AsmBox.Text != " " &&
                !AsmBox.Text.All(char.IsWhiteSpace) && !string.IsNullOrWhiteSpace(AsmBox.Text) &&
                AsmBox.Text != " Drag assembly drop here")
                DestSFD.FileName = Path.GetFileNameWithoutExtension(AsmBox.Text) + "_protected" + Path.GetExtension(AsmBox.Text);
            else
                DestSFD.FileName = string.Empty;

            DestSFD.Title = "Choose destination location";
            DestSFD.Filter = "Destination location(*.exe, *.dll)|*.exe;*.dll|All files(*.*)|*.*";

            if (DestSFD.ShowDialog() == DialogResult.OK)
            {
                string fileLocation = DestSFD.FileName;
                if (fileLocation.Length > 0)
                {
                    DestinationBox.Text = fileLocation;

                    if (!string.IsNullOrEmpty(AsmBox.Text) && AsmBox.Text != " Drag assembly drop here")
                        ShowLogsPageAndProtectCheckButton.Enabled = true;
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        #endregion

        #region SNK Group Events
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        private void ActiveSNK_Toggled(object sender, EventArgs e)
        {
            if (ActiveSNK.IsOn)
            {
                SNKLocationBox.Enabled = true;
                SNKPasswordBox.Enabled = true;
                BrowseSNKFileButton.Enabled = true;
            }
            else
            {
                SNKLocationBox.Enabled = false;
                SNKPasswordBox.Enabled = false;
                BrowseSNKFileButton.Enabled = false;
            }
        }

        private void BrowseSNKFileButton_Click(object sender, EventArgs e)
        {
            OpenFileDialog SNKOFD = new OpenFileDialog();
            SNKOFD.FileName = string.Empty;
            SNKOFD.Title = "Choose Strong Name Key";
            SNKOFD.Filter = "Strong Strong Name Key(*.pfx, *.snk)|*.pfx;*.snk";
            SNKOFD.CheckFileExists = true;

            if (SNKOFD.ShowDialog() == DialogResult.OK)
            {
                string snkFileLocation = SNKOFD.FileName;
                if (snkFileLocation.Length > 0)
                {
                    SNKLocationBox.Text = snkFileLocation;
                }
            }
        }

        private void SNKLocationBox_DragDrop(object sender, DragEventArgs e)
        {
            object data = e.Data.GetData(DataFormats.FileDrop);
            if (data != null)
            {
                string[] array = data as string[];
                if (array.Length == 1)
                {
                    if (ActiveSNK.IsOn)
                    {
                        string snkFileLocation = array[0];

                        if (Path.GetExtension(snkFileLocation).ToLower() == ".snk" || Path.GetExtension(snkFileLocation).ToLower() == ".pfx")
                        {
                            SNKLocationBox.Text = snkFileLocation;
                        }
                        else
                            MessageBox.Show("Just \".snk and .pfx\" file!", "ERROR!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    else
                        MessageBox.Show("Please active SNK page!", "ERROR!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        #endregion
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        #endregion

        #region Functions Page
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        private void VirtualizeAllFunctionsToggle_Toggled(object sender, EventArgs e)
        {
            for (int i = 0; i < FunctionsCheckList.Items.Count; i++)
            {
                CheckedListBoxItem item = FunctionsCheckList.Items[i];

                if (VirtualizeAllFunctionsToggle.IsOn)
                    item.CheckState = CheckState.Checked;
                else
                    item.CheckState = CheckState.Unchecked;
            }

            for (int i = 0; i < TempMethodList.Count; i++)
            {
                CheckedListBoxItem Tempitem = TempMethodList[i];

                if (VirtualizeAllFunctionsToggle.IsOn)
                    Tempitem.CheckState = CheckState.Checked;
                else
                    Tempitem.CheckState = CheckState.Unchecked;
            }
        }

        private void FunctionSearchBox_TextChanged(object sender, EventArgs e)
        {
            string search = FunctionSearchBox.Text;

            if (!string.IsNullOrWhiteSpace(search))
            {
                for (int num = FunctionsCheckList.Items.Count - 1; num >= 0; num--)
                {
                    FunctionsCheckList.Items.RemoveAt(num);
                }
                {
                    foreach (var tempMethods in TempMethodList)
                    {
                        if (tempMethods.Value.ToString().ToUpper().Contains(search.ToUpper()) || tempMethods.Value.ToString().ToLower().Contains(search.ToLower()) ||
                            tempMethods.Value.ToString().ToUpper(new CultureInfo("en", false)).Contains(search.ToUpper(new CultureInfo("en", false))) || tempMethods.Value.ToString().ToLower(new CultureInfo("en", false)).Contains(search.ToLower(new CultureInfo("en", false))) ||
                            FunctionsCheckList.Items.Contains(search))
                        {
                            FunctionsCheckList.Items.Add(tempMethods);
                        }
                    }

                    return;
                }
            }

            foreach (var tempMethods in TempMethodList)
                if (!FunctionsCheckList.Items.Contains(tempMethods))
                    FunctionsCheckList.Items.Add(tempMethods);
        }
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        #endregion

        #region Runtime Settings Page
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        private void RandomGenerateRuntimeNameButton_Click(object sender, EventArgs e)
        {
            RuntimeNameBox.Text = $"{ Guid.NewGuid().ToString("n") }.dll";
        }
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        #endregion

        private void Main_Load(object sender, EventArgs e)
        {
            // Null
        }

        private void Main_FormClosed(object sender, FormClosedEventArgs e)
        {
            EXECModule?.Dispose();
        }

        private void Main_FormClosing(object sender, FormClosingEventArgs e)
        {
            EXECModule?.Dispose();
        }
    }
}
