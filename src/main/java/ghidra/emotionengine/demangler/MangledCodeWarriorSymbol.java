/*
 * Copyright Cuyler36
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.emotionengine.demangler;

import java.util.*;

import ghidra.app.util.demangler.*;

class MangledCodeWarriorSymbol {

	private static final Map<String, String> OPERATOR_MAP = getOperatorMap();

	private String str;
	private boolean containsInvalidSpecifier;

	private MangledCodeWarriorSymbol(String g) {
		this.str = g;
	}

	private String cw(int n) {
		String g = str.substring(0, n);
		str = str.substring(n);
		return g;
	}

	private char hd() {
		return str.isEmpty() ? 0 : str.charAt(0);
	}

	private boolean isConstFunc() {
		if ((str.isEmpty() || str.length() < 2)) {
			return false;
		}
		return str.startsWith("CF") || str.startsWith("cF");
	}

	private char tk() {
		char hd = hd();
		cw(1);
		return hd;
	}

	private int nextInteger(char initial) {
		int value = initial - '0';

		while (Character.isDigit(hd()))
			value = value * 10 + (tk() - '0');

		return value;
	}

	private int nextInteger() {
		assert Character.isDigit(hd());
		return nextInteger(tk());
	}

	private boolean hasFunction() {
		return hd() == 'F';
	}

	private DemangledTemplate nextTemplate() {
		assert hd() == '<';

		// Parse a type, then look for the comma.
		var template = new DemangledTemplate();
		while (true) {
			var tok = tk();
			if (tok == '>')
				break;
			assert tok == '<' || tok == ',';
			var type = this.nextType();
			template.addParameter(type);
		}
		return template;
	}

	private static void demangleTemplates(DemangledDataType o) {
		var name = o.getName();
		var lb = name.indexOf('<');
		if (lb < 0)
			return;
		var rb = name.lastIndexOf('>');
		var parser = new MangledCodeWarriorSymbol(name.substring(lb, rb + 1));
		var template = parser.nextTemplate();
		o.setName(name.substring(0, lb));
		for (var param : template.getParameters()) {
			if (param.isPrimitive()) {
				o.setName(name.substring(0, lb) + template.toTemplate());
				break;
			}
		}

		o.setTemplate(template);
	}

	private static void demangleTemplates(DemangledFunction o) {
		var name = o.getName();
		var lb = name.indexOf('<');
		if (lb < 0)
			return;
		var rb = name.lastIndexOf('>');
		var parser = new MangledCodeWarriorSymbol(name.substring(lb, rb + 1));
		o.setName(name.substring(0, lb));
		o.setTemplate(parser.nextTemplate());
	}

	public static DemangledObject demangleSymbol(String symbolName) {
		// If it doesn't have a __, then it's not mangled.
		if (!symbolName.contains("__"))
			return null;

		// If we start with "@x@", then we're a virtual thunk, with "x" being the offset to the this pointer.
		boolean isThunk = false;
		if (symbolName.startsWith("@")) {
			int thunkAddrIdx = symbolName.lastIndexOf('@');
			symbolName = symbolName.substring(thunkAddrIdx + 1);
			isThunk = true;
		}

		int firstDunder = symbolName.indexOf("__", 1);
		// If the symbol starts with __, exit.
		if (firstDunder < 0 || firstDunder+2 >= symbolName.length())
			return null;

		// Ensure that any trailing underscores in the function name are accounted for
		while (symbolName.charAt(firstDunder + 2) == '_') {
			firstDunder++;
		}

		String parameters = symbolName.substring(firstDunder + 2);
		// After the dunder comes the class, if it exists, followed by 'F', followed by parameters.
		var demangler = new MangledCodeWarriorSymbol(parameters);

		DemangledDataType parentClass = null;
		if (!demangler.hasFunction())
			parentClass = demangler.nextType();

		var isConstFunc = demangler.isConstFunc();
		if (isConstFunc || demangler.hasFunction()) {
			DemangledFunction d = demangler.nextFunction(parentClass, symbolName);

			if (isThunk)
				d.setThunk(true);

			String functionName = symbolName.substring(0, firstDunder);
			String operatorName = demangleSpecialOperator(functionName);

			if (operatorName != null) {
				d.setOverloadedOperator(true);
				d.setName(operatorName);
			} else {
				if (functionName.equals("__ct"))
					functionName = parentClass.getName();
				else if (functionName.equals("__dt"))
					functionName = "~" + parentClass.getName();

				d.setName(functionName);

				MangledCodeWarriorSymbol.demangleTemplates(d);
			}

			if (demangler.containsInvalidSpecifier)
				return null;

			return d;
		}

		// It could be a member or vtable
		if (demangler.str.isEmpty()) {
			if (symbolName.startsWith("__vt__")) {
				return new DemangledMetrowerksVtable(symbolName, parentClass);
			}
			if (symbolName.startsWith("__RTTI__")) {
				return new DemangledMetrowerksRtti(symbolName, parentClass);
			}
			var member = new DemangledVariable(symbolName, null, symbolName.substring(0, firstDunder));

			if (parentClass != null) {
				var namespace = parentClass.getNamespace();
				var className = parentClass.getDemangledName();
				// If the class has a namespace, include that as well.
				if (parentClass.getTemplate() != null)
					className += parentClass.getTemplate().toTemplate();
				var classNamespace = new DemangledType(null, null, className);
				classNamespace.setNamespace(namespace);
				member.setNamespace(classNamespace);
			}

			return member;
		}

		return null;
	}

	private DemangledFunction nextFunction(DemangledDataType parentClass, String mangled) {
		char tok = tk();

		DemangledFunction func;
		if (parentClass != null) {
			func = new DemangledFunction(mangled, null, null);
			func.setCallingConvention("__thiscall");
		} else {
			func = new DemangledFunction(mangled, null, null);
			func.setCallingConvention("__stdcall");
		}

		if (tok == 'C') {
			func.setTrailingConst();
			tok = tk();
		}
		else if (tok == 'c') {
			func.setConst(true);
			tok = tk();
		}
		assert tok == 'F';

		// Parse parameters.
		while (true) {
			if (this.str.length() == 0)
				break;

			tok = hd();
			if (tok == '_') {
				tk();
				func.setReturnType(this.nextType());
			} else {
				func.addParameter(this.nextType());
			}
		}

		if (parentClass != null) {
			var namespace = parentClass.getNamespace();
			var className = parentClass.getDemangledName();
			// If the class has a namespace, include that as well.
			if (parentClass.getTemplate() != null)
				className += parentClass.getTemplate().toTemplate();
			var classNamespace = new DemangledType(mangled, className, className);
			classNamespace.setNamespace(namespace);
			func.setNamespace(classNamespace);
		}

		return func;
	}

	private DemangledDataType nextType() {
		char tok = tk();
		DemangledDataType d;

		switch (tok) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				if (str.isBlank()) {
					// templated return type
					return new DemangledDataType(null, null, DemangledDataType.VOID);
				}
				// Name or literal integer. Literal integers can show up in template parameters.
				int value = nextInteger(tok);
				if (hd() == '>' || hd() == ',') {
					// Literal integer (template)
					return new DemangledDataType(null, null, "" + value);
				}
				// Name.
				d = new DemangledDataType(null, null, cw(value));
				demangleTemplates(d);
				return d;
			case 'Q':
				// Qualified name.
				int compCount = tk() - '0';

				var names = new ArrayList<String>();
				for (var i = 0; i < compCount; i++) {
					int length = nextInteger();
					names.add(cw(length));
				}

				d = new DemangledDataType(null, null, names.get(compCount - 1));
				demangleTemplates(d);
				d.setNamespace(convertToNamespaces(names.subList(0, names.size() - 1)));
				return d;
			case 'F':
				var func = new DemangledFunctionPointer(null, null);

				// Parse parameters.
				while (true) {
					if (str.length() == 0)
						break;

					tok = hd();

					if (tok == '_') {
						tk();
						func.setReturnType(nextType());
						break;
					}

					func.addParameter(this.nextType());
				}

				demangleTemplates(func);

				return func;
			case 'P':
				d = nextType();
				d.incrementPointerLevels();
				return d;
			case 'A':
				var arraySize = nextInteger();
				var typeSeparator = tk();
				assert typeSeparator  == '_';
				d = nextType();
				d.setArray(arraySize);
				return d;
			case 'R':
				d = nextType();
				d.setReference();
				return d;
			case 'C':
				d = nextType();
				d.setConst();
				return d;
			case 'U':
				d = nextType();
				d.setUnsigned();
				return d;
			case 'S':
				d = nextType();
				d.setSigned();
				return d;
			case 'M':
				int length = nextInteger();
				var scope = cw(length);
				d = nextType();
				d.setMemberScope(scope);
				return d;
			case 'i':
				return new DemangledDataType(null, null, DemangledDataType.INT);
			case 'l':
				return new DemangledDataType(null, null, DemangledDataType.LONG);
			case 'x':
				return new DemangledDataType(null, null, DemangledDataType.LONG_LONG);
			case 'b':
				return new DemangledDataType(null, null, DemangledDataType.BOOL);
			case 'c':
				return new DemangledDataType(null, null, DemangledDataType.CHAR);
			case 's':
				return new DemangledDataType(null, null, DemangledDataType.SHORT);
			case 'f':
				return new DemangledDataType(null, null, DemangledDataType.FLOAT);
			case 'd':
				return new DemangledDataType(null, null, DemangledDataType.DOUBLE);
			case 'w':
				return new DemangledDataType(null, null, DemangledDataType.WCHAR_T);
			case 'v':
				return new DemangledDataType(null, null, DemangledDataType.VOID);
			case 'e':
				return new DemangledDataType(null, null, DemangledDataType.VARARGS);
			default:
				// Unknown.

				// This is here in case the __ is preceded by more underscores.
				containsInvalidSpecifier |= tok != '_';
				return new DemangledDataType(null, null, DemangledDataType.UNDEFINED);
		}
	}

	private static String demangleSpecialOperator(String symbolName) {
		if (symbolName.startsWith("__")) {
			String opName = symbolName.substring(2);
			return OPERATOR_MAP.get(opName);
		}
		return null;
	}

	private static DemangledType convertToNamespaces(List<String> names) {
		if (names.size() == 0) {
			return null;
		}
		int index = names.size() - 1;
		DemangledType myNamespace = new DemangledType(null, null, names.get(index));
		DemangledType namespace = myNamespace;
		while (--index >= 0) {
			DemangledType parentNamespace = new DemangledType(null, null, names.get(index));
			namespace.setNamespace(parentNamespace);
			namespace = parentNamespace;
		}
		return myNamespace;
	}

	private static Map<String, String> getOperatorMap() {

		Map<String, String> operatorMap = Map.ofEntries(
			Map.entry("nw", "operator new"),
			Map.entry("nwa", "operator new[]"),
			Map.entry("dl", "operator delete"),
			Map.entry("dla", "operator delete[]"),
			Map.entry("pl", "operator +"),
			Map.entry("mi", "operator -"),
			Map.entry("ml", "operator *"),
			Map.entry("dv", "operator /"),
			Map.entry("md", "operator %"),
			Map.entry("er", "operator ^"),
			Map.entry("adv", "operator /="),
			Map.entry("or", "operator |"),
			Map.entry("co", "operator ~"),
			Map.entry("nt", "operator !"),
			Map.entry("as", "operator ="),
			Map.entry("lt", "operator <"),
			Map.entry("gt", "operator >"),
			Map.entry("apl", "operator +="),
			Map.entry("ami", "operator -="),
			Map.entry("amu", "operator *="),
			Map.entry("amd", "operator %="),
			Map.entry("aer", "operator ^="),
			Map.entry("aad", "operator &="),
			Map.entry("aor", "operator |="),
			Map.entry("ls", "operator <<"),
			Map.entry("rs", "operator >>"),
			Map.entry("ars", "operator >>="),
			Map.entry("als", "operator <<="),
			Map.entry("eq", "operator =="),
			Map.entry("ne", "operator !="),
			Map.entry("le", "operator <="),
			Map.entry("aa", "operator &&"),
			Map.entry("oo", "operator ||"),
			Map.entry("pp", "operator ++"),
			Map.entry("mm", "operator --"),
			Map.entry("cl", "operator ()"),
			Map.entry("vc", "operator []"),
			Map.entry("rf", "operator ->"),
			Map.entry("cm", "operator ,"),
			Map.entry("rm", "operator ->*")
		);

		return Collections.unmodifiableMap(new HashMap<>(operatorMap));
	}

	public static void main(String[] args) {
		// __vt__Q23std9exception
		// __RTTI__Q23std9exception
		var demangledType = MangledCodeWarriorSymbol.demangleSymbol("__ct__Q43std3tr16detail383function_imp<PFPCcPCc_v,Q43std3tr16detail334bound_func<v,Q43std3tr16detail59mem_fn_2<v,Q53scn4step7gimmick9shipevent9ShipEvent,PCc,PCc>,Q33std3tr1228tuple<PQ53scn4step7gimmick9shipevent9ShipEvent,Q53std3tr112placeholders6detail5ph<1>,Q53std3tr112placeholders6detail5ph<2>,Q33std3tr13nat,Q33std3tr13nat,Q33std3tr13nat,Q33std3tr13nat,Q33std3tr13nat,Q33std3tr13nat,Q33std3tr13nat>>,0,1>FRCQ43std3tr16detail383function_imp<PFPCcPCc_v,Q43std3tr16detail334bound_func<v,Q43std3tr16detail59mem_fn_2<v,Q53scn4step7gimmick9shipevent9ShipEvent,PCc,PCc>,Q33std3tr1228tuple<PQ53scn4step7gimmick9shipevent9ShipEvent,Q53std3tr112placeholders6detail5ph<1>,Q53std3tr112placeholders6detail5ph<2>,Q33std3tr13nat,Q33std3tr13nat,Q33std3tr13nat,Q33std3tr13nat,Q33std3tr13nat,Q33std3tr13nat,Q33std3tr13nat>>,0,1>");
		System.out.println(demangledType.getSignature(true));
	}
}
