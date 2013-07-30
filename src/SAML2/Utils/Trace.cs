using System;
using System.Diagnostics;
using SAML2.Properties;

namespace SAML2.Utils
{
    /// <summary>
    /// Trace class. Can be used to trace. To ensure that tracing is enabled, you should make a call to "ShouldTrace"
    /// <example>
    ///     Put this in config to enable trace at the Warning level.
    ///    <system.diagnostics>
    ///    <trace autoflush="true" ></trace>
    ///    <sources>
    ///       <source name="SAML2" switchValue="Verbose">
    ///            <listeners>
    ///                <add name="trace"/>
    ///            </listeners>
    ///        </source>
    ///    </sources>
    ///    <sharedListeners>
    ///        <add name="trace" type="System.Diagnostics.XmlWriterTraceListener" initializeData="C:\logs\saml2.tracelog"/>
    ///    </sharedListeners>
    ///    </system.diagnostics>
    /// </example>
    /// </summary>
    public static class Trace
    {
        private readonly static TraceSource _source;

        static Trace()
        {
            _source = new TraceSource("SAML2");
        }

        /// <summary>
        /// Write data to tracesource. If a trace source is configured, and the Event Type is allowed to write. A message will be 
        /// traced.
        /// </summary>
        /// <param name="eventType">The trace level</param>
        /// <param name="message">The message</param>
        public static void TraceData(TraceEventType eventType, params string [] message)
        {
            _source.TraceData(eventType, 0, message);
        }

        /// <summary>
        /// Convenience helper for writing a trace data event when a method call starts
        /// </summary>
        public static void TraceMethodCalled(Type t, string methodname)
        {
            if (ShouldTrace(TraceEventType.Information))
                TraceData(TraceEventType.Information, CreateTraceString(t, methodname, Tracing.Called));
        }

        /// <summary>
        /// Convenience helper for writing a trace data event when a method call is done
        /// </summary>
        public static void TraceMethodDone(Type t, string methodname)
        {
            if (ShouldTrace(TraceEventType.Information))
                TraceData(TraceEventType.Information, CreateTraceString(t, methodname, Tracing.Done));
        }

        /// <summary>
        /// Ask the trace if a tracelevel is enabled. Use this if you want to determine if a message should be traced, before
        /// you build a complicated trace message.
        /// </summary>
        /// <param name="eventType">The tracelevel.</param>
        /// <returns>True if the message will be logged.</returns>
        public static bool ShouldTrace(TraceEventType eventType)
        {
            return _source.Switch.ShouldTrace(eventType);
        }

        /// <summary>
        /// Utility function for commonly formatted trace entries
        /// </summary>
        public static string CreateTraceString(Type t, string methodname, string postfix)
        {
            return String.Format("{0}.{1} {2}", (t == null ? "<notype>" : t.FullName), methodname ?? "<nomethod>", postfix ?? String.Empty);
        }

        /// <summary>
        /// Utility function for commonly formatted trace entries
        /// </summary>
        public static string CreateTraceString(Type t, string methodname)
        {
            return CreateTraceString(t, methodname, null);
        }
    }
}