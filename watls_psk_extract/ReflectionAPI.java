import java.lang.ClassLoader;
import java.lang.reflect.Method;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;


public class ReflectionAPI
{
    private static String getSimpleName(Object instance)
    {
        String simpleName = "?";

        if(instance != null)
            simpleName = instance.getClass().getSimpleName();

        return simpleName;
    }


    private static String getCauseSimpleName(Exception exception)
    {
        return getSimpleName(exception.getCause());
    }


    public static Class<?> getClass(String name)
    {
        Class<?> clazz = null;

        try
        {
            clazz = Class.forName(name);
        }
        catch(ClassNotFoundException exception)
        {
            System.out.println(String.format("ReflectionAPI::getClass(%s) ClassNotFoundException", name));
        }

        return clazz;
    }

    public static Class<?> getClass(ClassLoader classLoader, String name)
    {
        Class<?> clazz = null;

        try
        {
            // clazz = classLoader.loadClass(name);
            clazz = Class.forName(name, true, classLoader);
        }
        catch(ClassNotFoundException exception)
        {
            System.out.println(String.format("ReflectionAPI::getClass(%s) ClassNotFoundException", name));
        }

        return clazz;
    }


    public static Class<?> getArrayClass(String name)
    {
        return getClass(String.format("[L%s;", name));
    }


    public static Class<?> getArrayClass(ClassLoader classLoader, String name)
    {
        return getClass(classLoader, String.format("[L%s;", name));
    }


    public static Field getField(Class<?> clazz, String name)
    {
        Field field = null;

        try
        {
            field = clazz.getDeclaredField(name);
            field.setAccessible(true);
        }
        catch(ReflectiveOperationException exception)
        {
            System.out.println(String.format("ReflectionAPI::getField(%s, %s) %s: %s",
                clazz.getSimpleName(), name, getCauseSimpleName(exception),
                exception.getMessage()));
        }

        return field;
    }


    public static Method getMethod(Class<?> clazz, String name, Class<?>... parameters)
    {
        Method method = null;

        try
        {
            method = clazz.getDeclaredMethod(name, parameters);
            method.setAccessible(true);
        }
        catch(ReflectiveOperationException exception)
        {
            System.out.println(String.format("ReflectionAPI::getMethod(%s, %s) %s: %s",
                clazz.getSimpleName(), name, getCauseSimpleName(exception),
                exception.getMessage()));
        }

        return method;
    }


    public static Object callMethod(Method method, Object instance, Object... parameters)
        throws Exception
    {
        Object ret = null;

        try
        {
            ret = method.invoke(instance, parameters);
        }
        catch(InvocationTargetException exception)
        {
            //
            // We need this type of exceptions to be thrown, so that we know
            // when the target program misbehaves.
            //
            throw (Exception)exception.getTargetException();
        }
        catch(ReflectiveOperationException exception)
        {
            System.out.println(String.format("ReflectionAPI::callMethod(%s, %s) %s: %s",
                method.getDeclaringClass().getSimpleName(), method.getName(),
                getCauseSimpleName(exception), exception.getMessage()));
        }

        return ret;
    }


    public static Constructor<?> getConstructor(Class<?> clazz, Class<?>... parameters)
    {
        Constructor<?> constructor = null;

        try
        {
            constructor = clazz.getDeclaredConstructor(parameters);
            constructor.setAccessible(true);
        }
        catch(ReflectiveOperationException exception)
        {
            System.out.println(String.format("ReflectionAPI::getConstructor(%s) %s: %s",
                clazz.getSimpleName(), getCauseSimpleName(exception),
                exception.getMessage()));
        }

        return constructor;
    }


    public static Object callConstructor(Constructor<?> constructor, Object... parameters)
    {
        Object instance = null;

        try
        {
            instance = constructor.newInstance(parameters);
        }
        catch(ReflectiveOperationException exception)
        {
            System.out.println(String.format("ReflectionAPI::callConstructor(%s, %s) %s: %s",
                constructor.getDeclaringClass().getSimpleName(), constructor.getName(),
                getCauseSimpleName(exception), exception.getMessage()));
        }

        return instance;
    }


    public static void setFieldValue(Field field, Object instance, Object value)
    {
        try
        {
            field.set(instance, value);
        }
        catch(ReflectiveOperationException exception)
        {
            System.out.println(String.format("ReflectionAPI::setFieldValue(%s, %s) %s: %s",
                field.getName(), getSimpleName(instance), getCauseSimpleName(exception),
                exception.getMessage()));
        }
    }


    public static Object getFieldValue(Field field, Object instance)
    {
        Object value = null;

        try
        {
            value = field.get(instance);
        }
        catch(ReflectiveOperationException exception)
        {
            System.out.println(String.format("ReflectionAPI::getFieldValue(%s, %s) %s: %s",
                field.getName(), getSimpleName(instance), getCauseSimpleName(exception),
                exception.getMessage()));
        }

        return value;
    }
}

