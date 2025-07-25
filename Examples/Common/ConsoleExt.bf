using System;

namespace Beef_Net_Common
{
    #if BF_PLATFORM_WINDOWS
	[CRepr]
	struct ConsoleKeyInfo
	{
		private char8 _keyChar;
		private ConsoleKey _key;
		private ConsoleModifiers _mods;

		public this(char8 keyChar, ConsoleKey key, bool shift, bool alt, bool control)
		{
		    // Limit ConsoleKey values to 0 to 255, but don't check whether the
		    // key is a valid value in our ConsoleKey enum.  There are a few 
		    // values in that enum that we didn't define, and reserved keys 
		    // that might start showing up on keyboards in a few years.
		    Runtime.Assert(((int)key) > 0 && ((int)key) < 255);

		    _keyChar = keyChar;
		    _key = key;
		    _mods = 0;

		    if (shift)
		        _mods |= ConsoleModifiers.Shift;

		    if (alt)
		        _mods |= ConsoleModifiers.Alt;

		    if (control)
		        _mods |= ConsoleModifiers.Control;
		}

		public char8 KeyChar
		{
		    get { return _keyChar; }
		}

		public ConsoleKey Key
		{
		    get { return _key; }
		}

		public ConsoleModifiers Modifiers
		{
		    get { return _mods; }
		}

		public bool Equals(Object value)
		{
		    if (value is ConsoleKeyInfo)
		        return Equals((ConsoleKeyInfo)value);
		    else
		        return false;
		}

		public bool Equals(ConsoleKeyInfo obj) =>
			obj._keyChar == _keyChar && obj._key == _key && obj._mods == _mods;

		public static bool operator ==(ConsoleKeyInfo a, ConsoleKeyInfo b) =>
			a.Equals(b);

		public static bool operator !=(ConsoleKeyInfo a, ConsoleKeyInfo b) =>
			!(a == b);

		public int GetHashCode() =>
			(int)_keyChar | (int) _mods;
	}

	enum ConsoleKey : uint16
	{
	    Backspace  = 0x8,
	    Tab = 0x9,
	    // 0xA,  // Reserved
	    // 0xB,  // Reserved
	    Clear = 0xC,
	    Enter = 0xD,
	    // 0E-0F,  // Undefined
	    // SHIFT = 0x10,
	    // CONTROL = 0x11,
	    // Alt = 0x12,
	    Pause = 0x13,
	    // CAPSLOCK = 0x14,
	    // Kana = 0x15,  // Ime Mode
	    // Hangul = 0x15,  // Ime Mode
	    // 0x16,  // Undefined
	    // Junja = 0x17,  // Ime Mode
	    // Final = 0x18,  // Ime Mode
	    // Hanja = 0x19,  // Ime Mode
	    // Kanji = 0x19,  // Ime Mode
	    // 0x1A,  // Undefined
	    Escape = 0x1B,
	    // Convert = 0x1C,  // Ime Mode
	    // NonConvert = 0x1D,  // Ime Mode
	    // Accept = 0x1E,  // Ime Mode
	    // ModeChange = 0x1F,  // Ime Mode
	    Spacebar = 0x20,
	    PageUp = 0x21,
	    PageDown = 0x22,
	    End = 0x23,
	    Home = 0x24,
	    LeftArrow = 0x25,
	    UpArrow = 0x26,
	    RightArrow = 0x27,
	    DownArrow = 0x28,
	    Select = 0x29,
	    Print = 0x2A,
	    Execute = 0x2B,
	    PrintScreen = 0x2C,
	    Insert = 0x2D,
	    Delete = 0x2E,
	    Help = 0x2F,
	    D0 = 0x30,  // 0 through 9
	    D1 = 0x31,
	    D2 = 0x32,
	    D3 = 0x33,
	    D4 = 0x34,
	    D5 = 0x35,
	    D6 = 0x36,
	    D7 = 0x37,
	    D8 = 0x38,
	    D9 = 0x39,
	    // 3A-40 ,  // Undefined
	    A = 0x41,
	    B = 0x42,
	    C = 0x43,
	    D = 0x44,
	    E = 0x45,
	    F = 0x46,
	    G = 0x47,
	    H = 0x48,
	    I = 0x49,
	    J = 0x4A,
	    K = 0x4B,
	    L = 0x4C,
	    M = 0x4D,
	    N = 0x4E,
	    O = 0x4F,
	    P = 0x50,
	    Q = 0x51,
	    R = 0x52,
	    S = 0x53,
	    T = 0x54,
	    U = 0x55,
	    V = 0x56,
	    W = 0x57,
	    X = 0x58,
	    Y = 0x59,
	    Z = 0x5A,
	    LeftWindows = 0x5B,  // Microsoft Natural keyboard
	    RightWindows = 0x5C,  // Microsoft Natural keyboard
	    Applications = 0x5D,  // Microsoft Natural keyboard
	    // 5E ,  // Reserved
	    Sleep = 0x5F,  // Computer Sleep Key
	    NumPad0 = 0x60,
	    NumPad1 = 0x61,
	    NumPad2 = 0x62,
	    NumPad3 = 0x63,
	    NumPad4 = 0x64,
	    NumPad5 = 0x65,
	    NumPad6 = 0x66,
	    NumPad7 = 0x67,
	    NumPad8 = 0x68,
	    NumPad9 = 0x69,
	    Multiply = 0x6A,
	    Add = 0x6B,
	    Separator = 0x6C,
	    Subtract = 0x6D,
	    Decimal = 0x6E,
	    Divide = 0x6F,
	    F1 = 0x70,
	    F2 = 0x71,
	    F3 = 0x72,
	    F4 = 0x73,
	    F5 = 0x74,
	    F6 = 0x75,
	    F7 = 0x76,
	    F8 = 0x77,
	    F9 = 0x78,
	    F10 = 0x79,
	    F11 = 0x7A,
	    F12 = 0x7B,
	    F13 = 0x7C,
	    F14 = 0x7D,
	    F15 = 0x7E,
	    F16 = 0x7F,
	    F17 = 0x80,
	    F18 = 0x81,
	    F19 = 0x82,
	    F20 = 0x83,
	    F21 = 0x84,
	    F22 = 0x85,
	    F23 = 0x86,
	    F24 = 0x87,
	    // 88-8F,  // Undefined
	    // NumberLock = 0x90,
	    // ScrollLock = 0x91,
	    // 0x92,  // OEM Specific
	    // 97-9F ,  // Undefined
	    // LeftShift = 0xA0,
	    // RightShift = 0xA1,
	    // LeftControl = 0xA2,
	    // RightControl = 0xA3,
	    // LeftAlt = 0xA4,
	    // RightAlt = 0xA5,
	    BrowserBack = 0xA6,  // Windows 2000/XP
	    BrowserForward = 0xA7,  // Windows 2000/XP
	    BrowserRefresh = 0xA8,  // Windows 2000/XP
	    BrowserStop = 0xA9,  // Windows 2000/XP
	    BrowserSearch = 0xAA,  // Windows 2000/XP
	    BrowserFavorites = 0xAB,  // Windows 2000/XP
	    BrowserHome = 0xAC,  // Windows 2000/XP
	    VolumeMute = 0xAD,  // Windows 2000/XP
	    VolumeDown = 0xAE,  // Windows 2000/XP
	    VolumeUp = 0xAF,  // Windows 2000/XP
	    MediaNext = 0xB0,  // Windows 2000/XP
	    MediaPrevious = 0xB1,  // Windows 2000/XP
	    MediaStop = 0xB2,  // Windows 2000/XP
	    MediaPlay = 0xB3,  // Windows 2000/XP
	    LaunchMail = 0xB4,  // Windows 2000/XP
	    LaunchMediaSelect = 0xB5,  // Windows 2000/XP
	    LaunchApp1 = 0xB6,  // Windows 2000/XP
	    LaunchApp2 = 0xB7,  // Windows 2000/XP
	    // B8-B9,  // Reserved
	    Oem1 = 0xBA,  // Misc characters, varies by keyboard. For US standard, ;:
	    OemPlus = 0xBB,  // Misc characters, varies by keyboard. For US standard, +
	    OemComma = 0xBC,  // Misc characters, varies by keyboard. For US standard, ,
	    OemMinus = 0xBD,  // Misc characters, varies by keyboard. For US standard, -
	    OemPeriod = 0xBE,  // Misc characters, varies by keyboard. For US standard, .
	    Oem2 = 0xBF,  // Misc characters, varies by keyboard. For US standard, /?
	    Oem3 = 0xC0,  // Misc characters, varies by keyboard. For US standard, `~
	    // 0xC1,  // Reserved
	    // D8-DA,  // Unassigned
	    Oem4 = 0xDB,  // Misc characters, varies by keyboard. For US standard, [{
	    Oem5 = 0xDC,  // Misc characters, varies by keyboard. For US standard, \|
	    Oem6 = 0xDD,  // Misc characters, varies by keyboard. For US standard, ]}
	    Oem7 = 0xDE,  // Misc characters, varies by keyboard. For US standard,
	    Oem8 = 0xDF,  // Used for miscellaneous characters; it can vary by keyboard
	    // 0xE0,  // Reserved
	    // 0xE1,  // OEM specific
	    Oem102 = 0xE2,  // Win2K/XP: Either angle or backslash on RT 102-key keyboard
	    // 0xE3,  // OEM specific
	    Process = 0xE5,  // Windows: IME Process Key
	    // 0xE6,  // OEM specific
	    Packet = 0xE7,  // Win2K/XP: Used to pass Unicode chars as if keystrokes
	    // 0xE8,  // Unassigned
	    // 0xE9,  // OEM specific
	    Attention = 0xF6,
	    CrSel = 0xF7,
	    ExSel = 0xF8,
	    EraseEndOfFile = 0xF9,
	    Play = 0xFA,
	    Zoom = 0xFB,
	    NoName = 0xFC,  // Reserved
	    Pa1 = 0xFD,
	    OemClear = 0xFE,
	}

	enum ConsoleModifiers
	{
	    Alt = 1,
	    Shift = 2,
	    Control = 4
	}

	[CRepr]
	struct COORD
	{
		public int16 X;
		public int16 Y;
	}

	[CRepr, Ordered]
	struct KeyEventRecord
	{
	    public uint32 bKeyDown;
	    public uint16 wRepeatCount;
	    public ConsoleKey wVirtualKeyCode;
	    public uint16 wVirtualScanCode;
	    public CharU UChar;
	    public ControlKeyState dwControlKeyState;

		[CRepr, Union]
		public struct CharU
		{
			public char16 UnicodeChar;
			public char8 AsciiChar;
		}
	}

	[CRepr]
	struct MouseEventRecord
	{
	    public COORD mousePosition;
	    public uint16 buttonState;
	    public uint16 controlKeyState;
	    public uint16 eventFlags;
	}

	[CRepr]
	struct WindowBufferSizeRecord
	{
	    public COORD size;
	}

	[CRepr]
	struct MenuEventRecord
	{
	    public uint32 commandId;
	}

	[CRepr]
	struct FocusEventRecord
	{
	    public bool setFocus;
	}

	[CRepr]
	struct InputRecord
	{
	    public int16 eventType;
		public EventU Event;

		[CRepr, Union]
		public struct EventU
		{
			public KeyEventRecord keyEvent;
			public MouseEventRecord MouseEvent;
			public WindowBufferSizeRecord WindowBufferSizeEvent;
			public MenuEventRecord MenuEvent;
	    	public FocusEventRecord FocusEvent;
		}
	}

	enum ControlKeyState : uint32
	{
	    RightAltPressed =  0x0001,
	    LeftAltPressed =   0x0002,
	    RightCtrlPressed = 0x0004,
	    LeftCtrlPressed =  0x0008,
	    ShiftPressed =     0x0010,
	    NumLockOn =        0x0020,
	    ScrollLockOn =     0x0040,
	    CapsLockOn =       0x0080,
	    EnhancedKey =      0x0100
	}

	enum Handles : uint32
	{
		STD_INPUT = (uint32)-10,
		STD_OUTPUT = (uint32)-11,
		STD_ERROR = (uint32)-12
	}

	static class ConsoleExt
	{
		public const int16 KEY_EVENT = 1;
	
		public const int16 AltVKCode = 0x12;
	
		public const uint32 ENABLE_ECHO_INPUT             = 0x0004U;
		public const uint32 ENABLE_INSERT_MODE            = 0x0020U;
		public const uint32 ENABLE_LINE_INPUT             = 0x0002U;
		public const uint32 ENABLE_MOUSE_INPUT            = 0x0010U;
		public const uint32 ENABLE_PROCESSED_INPUT        = 0x0001U;
		public const uint32 ENABLE_QUICK_EDIT_MODE        = 0x0040U;
		public const uint32 ENABLE_WINDOW_INPUT           = 0x0008U;
		public const uint32 ENABLE_VIRTUAL_TERMINAL_INPUT = 0x0200U;
	
		public const uint32 ENABLE_PROCESSED_OUTPUT            = 0x0001U;
		public const uint32 ENABLE_WRAP_AT_EOL_OUTPUT          = 0x0002U;
		public const uint32 ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004U;
		public const uint32 DISABLE_NEWLINE_AUTO_RETURN        = 0x0008U;
		public const uint32 ENABLE_LVB_GRID_WORLDWIDE          = 0x0010U;
		
		private static void* _stdInFile = null;
		private static void* _stdOutFile = null;
        private static InputRecord _cachedInputRecord = .();

		[Import("kernel32.dll"), CLink, CallingConvention(.Stdcall)]
		public static extern void* GetStdHandle(Handles nStdHandle);
	
		[Import("kernel32.dll"), CLink, CallingConvention(.Stdcall)]
		private static extern bool GetNumberOfConsoleInputEvents(void* hConsoleInput, out uint32 numEvents);
	
		[Import("kernel32.dll"), CLink, CallingConvention(.Stdcall)]
		public static extern bool GetConsoleMode(void* hConsoleHandle, out uint32 dwMode);
	
		[Import("kernel32.dll"), CLink, CallingConvention(.Stdcall)]
		public static extern bool SetConsoleMode(void* hConsoleHandle, uint32 dwMode);
	
		[Import("kernel32.dll"), CLink, CallingConvention(.Stdcall)]
		private static extern bool PeekConsoleInputA(void* hConsoleInput, out InputRecord buffer, uint32 numInputRecords_UseOne, out uint32 numEventsRead);
	
		[Import("kernel32.dll"), CLink, CallingConvention(.Stdcall)]
		private static extern bool PeekConsoleInputW(void* hConsoleInput, out InputRecord buffer, uint32 numInputRecords_UseOne, out uint32 numEventsRead);

		private static bool PeekConsoleInput(void* hConsoleInput, out InputRecord buffer, uint32 numInputRecords_UseOne, out uint32 numEventsRead) =>
			PeekConsoleInputA(hConsoleInput, out buffer, numInputRecords_UseOne, out numEventsRead);
	
		[Import("kernel32.dll"), CLink, CallingConvention(.Stdcall)]
		private static extern bool ReadConsoleInputA(void* hConsoleInput, out InputRecord buffer, uint32 numInputRecords_UseOne, out uint32 numEventsRead);
	
		[Import("kernel32.dll"), CLink, CallingConvention(.Stdcall)]
		private static extern bool ReadConsoleInputW(void* hConsoleInput, out InputRecord buffer, uint32 numInputRecords_UseOne, out uint32 numEventsRead);

		private static bool ReadConsoleInput(void* hConsoleInput, out InputRecord buffer, uint32 numInputRecords_UseOne, out uint32 numEventsRead) =>
			ReadConsoleInputA(hConsoleInput, out buffer, numInputRecords_UseOne, out numEventsRead);
	
		private static bool IsKeyDownEvent(InputRecord ir) =>
			(ir.eventType == KEY_EVENT && ir.Event.keyEvent.bKeyDown > 0);
	
		private static bool IsModKey(InputRecord ir) {
		    // We should also skip over Shift, Control, and Alt, as well as caps lock.
		    // Apparently we don't need to check for 0xA0 through 0xA5, which are keys like 
		    // Left Control & Right Control. See the ConsoleKey enum for these values.
		    uint16 keyCode = ir.Event.keyEvent.wVirtualKeyCode.Underlying;
		    return ((keyCode >= 0x10 && keyCode <= 0x12) || keyCode == 0x14 || keyCode == 0x90 || keyCode == 0x91);
		}
	
		private static bool IsAltKeyDown(InputRecord ir) =>
		    ir.Event.keyEvent.dwControlKeyState.HasFlag(.LeftAltPressed) || ir.Event.keyEvent.dwControlKeyState.HasFlag(.RightAltPressed);

		public static void PrepHandles()
		{
			_stdInFile = ConsoleExt.GetStdHandle(Handles.STD_INPUT);
			_stdOutFile = ConsoleExt.GetStdHandle(Handles.STD_OUTPUT);
			uint32 dwMode = 0;

			ConsoleExt.GetConsoleMode(_stdOutFile, out dwMode);
			dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING; /* | DISABLE_NEWLINE_AUTO_RETURN*/
			ConsoleExt.SetConsoleMode(_stdOutFile, dwMode);
			ConsoleExt.SetConsoleMode(_stdInFile, ENABLE_ECHO_INPUT | ENABLE_INSERT_MODE | ENABLE_MOUSE_INPUT | ENABLE_QUICK_EDIT_MODE | ENABLE_WINDOW_INPUT);
		}

		public static bool IsKeyPressed()
		{
			InputRecord ir = ?;
			uint32 dump = ?;
			uint32 numEvents = ?;

			mixin ReadAndReturnFalse()
			{
				ReadConsoleInput(_stdInFile, out ir, 1, out dump);
				return false;
			}

			GetNumberOfConsoleInputEvents(_stdInFile, out numEvents);

			if (numEvents == 0)
				return false;

			bool r = PeekConsoleInput(_stdInFile, out ir, 1, out dump);

			if (!r)
				return false;

	        uint16 keyCode = ir.Event.keyEvent.wVirtualKeyCode.Underlying;

			if ((!IsKeyDownEvent(ir)) && keyCode != AltVKCode)
				ReadAndReturnFalse!();

	    	char8 ch = ir.Event.keyEvent.UChar.AsciiChar;

            if (ch == 0x0 && IsModKey(ir)) // Skip mod keys.
				ReadAndReturnFalse!();

			ConsoleKey key = ir.Event.keyEvent.wVirtualKeyCode;

			if (IsAltKeyDown(ir) && ((key >= ConsoleKey.NumPad0 && key <= ConsoleKey.NumPad9) ||
				(key == ConsoleKey.Clear) || (key == ConsoleKey.Insert) ||
				(key >= ConsoleKey.PageUp && key <= ConsoleKey.DownArrow)))
				ReadAndReturnFalse!();

	        return true;
		}
	
		public static ConsoleKeyInfo ReadKey(bool intercept)
		{
		    InputRecord ir = ?;
		    uint32 numEventsRead = 0;
		    bool r = false;

		    if (_cachedInputRecord.eventType == KEY_EVENT)
			{
		        // We had a previous keystroke with repeated characters.
		        ir = _cachedInputRecord;

		        if (_cachedInputRecord.Event.keyEvent.wRepeatCount == 0)
		            _cachedInputRecord.eventType = -1;
		        else
		            _cachedInputRecord.Event.keyEvent.wRepeatCount--;

		        // We will return one key from this method, so we decrement the
		        // repeatCount here, leaving the cachedInputRecord in the "queue".
		    }
			else
			{ // We did NOT have a previous keystroke with repeated characters:
		        while (true)
				{
		            r = ReadConsoleInput(_stdInFile, out ir, 1, out numEventsRead);

		            if (!r || numEventsRead == 0)
					{
		                // This will fail when stdin is redirected from a file or pipe. 
		                // We could theoretically call Console.Read here, but I 
		                // think we might do some things incorrectly then.
						Runtime.FatalError("Invalid Operation : Console Read Key On File");
		            }

		            uint16 keyCode = ir.Event.keyEvent.wVirtualKeyCode.Underlying;

		            // First check for non-keyboard events & discard them. Generally we tap into only KeyDown events and ignore the KeyUp events
		            // but it is possible that we are dealing with a Alt+NumPad unicode key sequence, the final unicode char is revealed only when
		            // the Alt key is released (i.e when the sequence is complete). To avoid noise, when the Alt key is down, we should eat up
		            // any intermediate key strokes (from NumPad) that collectively forms the Unicode character.

		            if ((!IsKeyDownEvent(ir)) && keyCode != AltVKCode)
		                continue;

		            char8 ch = ir.Event.keyEvent.UChar.AsciiChar;

		            // In a Alt+NumPad unicode sequence, when the alt key is released uChar will represent the final unicode character, we need to
		            // surface this. VirtualKeyCode for this event will be Alt from the Alt-Up key event. This is probably not the right code,
		            // especially when we don't expose ConsoleKey.Alt, so this will end up being the hex value (0x12). VK_PACKET comes very
		            // close to being useful and something that we could look into using for this purpose...

		            if (ch == 0x0 && IsModKey(ir)) // Skip mod keys.
		                continue;

		            // When Alt is down, it is possible that we are in the middle of a Alt+NumPad unicode sequence.
		            // Escape any intermediate NumPad keys whether NumLock is on or not (notepad behavior)
		            ConsoleKey key = ir.Event.keyEvent.wVirtualKeyCode;

		            if (IsAltKeyDown(ir) && ((key >= ConsoleKey.NumPad0 && key <= ConsoleKey.NumPad9) ||
						(key == ConsoleKey.Clear) || (key == ConsoleKey.Insert) ||
						(key >= ConsoleKey.PageUp && key <= ConsoleKey.DownArrow)))
		                continue;

		            if (ir.Event.keyEvent.wRepeatCount > 1)
					{
		                ir.Event.keyEvent.wRepeatCount--;
		                _cachedInputRecord = ir;
		            }

		            break;
		        }
		    }

		    ControlKeyState state = ir.Event.keyEvent.dwControlKeyState;
		    bool shift = state.HasFlag(.ShiftPressed);
		    bool alt = state.HasFlag(.LeftAltPressed) || state.HasFlag(.RightAltPressed);
		    bool control = state.HasFlag(.LeftCtrlPressed) || state.HasFlag(.RightCtrlPressed);

		    ConsoleKeyInfo info = .(ir.Event.keyEvent.UChar.AsciiChar, ir.Event.keyEvent.wVirtualKeyCode, shift, alt, control);

		    if (!intercept)
		        Console.Write(ir.Event.keyEvent.UChar.AsciiChar);

		    return info;
		}
	}
#else // Other Platforms
    static class ConsoleExt
    {
        public static void PrepHandles()
        {
        }

        public static void ReadKey(bool what)
        {
            Console.Read();
        }
    }
#endif
}
