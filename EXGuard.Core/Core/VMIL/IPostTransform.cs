﻿namespace EXGuard.Core.VMIL
{
    public interface IPostTransform
    {
        void Initialize(ILPostTransformer tr);
        void Transform(ILPostTransformer tr);
    }
}